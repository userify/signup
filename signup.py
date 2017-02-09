#! /usr/bin/env python

# Userify Cloud Signup
# Copyright (c) 2017 Userify Corporation

try:
    import json
except:
    import simplejson as json
import subprocess
import os, sys
import httplib
import base64
import string
import getpass
import socket
from pprint import pprint, pformat
import ssl
import tempfile

# recapture sdtin, since it's closed since we're
# coming in from a piped process..
sys.stdin = open('/dev/tty')

ssl_security_context = None
try:
    # fails on python < 2.6:
    import ssl
    # not avail in python < 2.7:
    ssl_security_context = (hasattr(ssl, '_create_unverified_context')
        and ssl._create_unverified_context() or None)
except:
    pass


# socket.setdefaulttimeout(60)


# try to read a public key..
USER = os.environ.get("USER", "")
HOME = os.environ.get("HOME", "")
# hopefully HOME isn't /root/ ...!
for HOMEDIR in ["/home/%s" % USER, "/home/ec2-user", "/home/ubuntu", "/home/centos", HOME]:
    SSH_KEYDIR = HOMEDIR + "/.ssh/authorized_keys" if HOMEDIR else ""
    SSH_PUBLIC_KEY = ""
    try:
        SSH_PUBLIC_KEY = open(SSH_KEYDIR).read().strip()
    except:
        pass
    if SSH_PUBLIC_KEY:
        break


def die(code, text):
    print ("Sorry! Something went wrong with this script!")
    print ("Please email support@userify.com "
          +"and we'll fix it asap!\n")
    print("%s %s" % (code, text))
    sys.exit(1)


class API:

    auth = ""
    https_proxy = ""
    https_proxy_port = 443
    debug = False

    def __init__(self, host="api.userify.com", port=443, prefix="/api/userify", debug=False):
        self.final_host = host
        self.final_port = port
        self._retrieve_https_proxy()
        self.prefix = prefix
        self.debug_log = []

    def log(self, msg):
        self.debug_log.append(str(msg))
        if self.debug: print msg

    def login(self, username, password):
        self.auth = "Basic " + base64.b64encode(
            ":".join((username, password)))

    def _retrieve_https_proxy(self):
        # thx Purinda Gunasekara @ News Corp:
        if 'https_proxy' in os.environ:
            self.https_proxy = os.environ['https_proxy'].strip()
            if self.https_proxy.startswith("http"):
                self.https_proxy = https_proxy.replace("https://","",1)
                self.https_proxy = https_proxy.replace("http://","",1)
                if ":" in self.https_proxy:
                    self.https_proxy, self.https_proxy_port = self.https_proxy.split(":")
                    self.https_proxy_port = int(''.join(c for c in self.https_proxy_port if c.isdigit()))

    def https(self, method, path, data=""):
        if ssl_security_context:
            reqobj = httplib.HTTPSConnection(
                self.https_proxy if self.https_proxy else self.final_host,
                self.https_proxy_port if self.https_proxy_port else self.final_port,
                timeout=20,
                context=ssl_security_context)
        else:
            reqobj = httplib.HTTPSConnection(
                self.https_proxy if self.https_proxy else self.final_host,
                self.https_proxy_port if self.https_proxy_port else self.final_port,
                timeout=20)
        self.log("NEW https connection %s" % reqobj)
        if self.https_proxy:
            self.log("Proxy %s:%s" % (self.final_host, self.final_port))
            reqobj.set_tunnel(self.final_host, self.final_port)
        self.log("Host: %s:%s" % (self.final_host, self.final_port))
        data = data or {}
        data['signup_version'] = "1.0"
        data = json.dumps(data)
        headers = {"Accept": "text/plain, */json"}
        if self.auth:
            headers["Authorization"] = self.auth
        self.log("%s %s" % (method, path))
        self.log(pformat(data))
        self.log(pformat(headers))
        try:
            reqobj.request(method, path, data, headers)
        except Exception, e:
            self.log("Error: %s" % e)
        return reqobj

    def _handle_error(self, text, handle_error=True):
        if handle_error and self.response.status != 200:
            self.log(self.response.status)
            if text and text.startswith('{"error": '):
                self.log(json.loads(text)["error"])
            else:
                self.log("%s %s" % (self.response.reason, text))
            self.log("Please try again at https://dashboard.userify.com")
            self.log("or email support@userify.com.")
            print("\n".join(self.debug_log))
            die(self.response.status, self.response.reason)

    def request(self, method, path, data=""):
        path = self.prefix.rstrip("/") + "/" + path.lstrip("/")
        reqobj = self.https(method, path, data)
        # reqobj.sock.settimeout(15)
        self.response = reqobj.getresponse()
        return self.response.read()

    def _handle_request(self, method, path, data, handle_error=True):
        response_data = self.request(method, path, data)
        if handle_error:
            self._handle_error(response_data, handle_error)
        data = json.loads(response_data) if response_data else {}
        return self.response, data

    def head(self, path, data="", handle_error=True):
        return self._handle_request("HEAD", path, data, handle_error=handle_error)

    def get(self, path, data="", handle_error=True):
        return self._handle_request("GET", path, data, handle_error=handle_error)

    def put(self, path, data, handle_error=True):
        return self._handle_request("PUT", path, data, handle_error=handle_error)

    def post(self, path, data, handle_error=True):
        return self._handle_request("POST", path, data, handle_error=handle_error)

    def delete(self, path, data="", handle_error=True):
        return self._handle_request("DELETE", path, data, handle_error=handle_error)


def qexec(cmd):
    print "exec: \"" + " ".join(cmd) + '"'
    try:
        subprocess.check_call(cmd)
    except Exception, e:
        print "ERROR executing %s" % " ".join(cmd)
        print e


def string_test(s, is_email=False):
    safe = (string.ascii_letters +
            string.digits + "_")
    if is_email:
        safe += "@.,+"
    s = s.strip().lower()
    if not s:
        return ""
    if not is_email and s[0] not in string.ascii_letters:
        print "Linux usernames must start with a Latin alphabet letter."
        return ""
    if is_email and (not "@" in s or len(s.split("@")) < 2):
        return ""
    for k in list(s):
        if k not in safe:
            print "Sorry, unsupported character: %s" % k
            return ""
    return s

def ask_username_password(api):

    print """A special note on Usernames..
    Usernames are in a global namespace across the entire cloud.  They must be
    unique in all of Userify to reduce security risk from overlapping or
    renamed usernames. If you have a particular username on Github, it's likely
    available here. You can even use your eamil address on most Linux
    distributions, and, don't worry -- of course you can change your username
    at any time. Usernames are only restricted on Userify Cloud, not Userify
    self-hosted (Enterprise and Professional).
    """

    username = password = ""
    if USER not in "ec2-user root ubuntu centos":
        uname = " [%s]" % USER
    else:
        uname = ""

    while not username:
        unameprompt = (" (or press Enter to try %s)" % uname) if uname else ""
        username = raw_input("\nPlease provide a username" + unameprompt + ": ")
        username = string_test(username)
        if not username:
            username = USER
        if not check_username(api, username):
            print "Username %s is already in use." % username
            username = uname = ""

    print """    Your password is secure. It does not stay on this computer, but
    is immediately sent via TLS pigeons to our server, where it is hashed with
    bcrypt and then the bcrypted password is encrypted in your profile with
    libsodium/NaCl. 
    
    Your profile is then housed on UV-sensitive paper in a thousand-year-old
    monastery on top of the world, guarded by the world's most fearsome giraffes.
    
    (Ok, that last part was completely made up, of course -- who ever saw a
    fearsome giraffe? -- but the bits about TLS, bcrypt, and libsodium were all
    true! If this isn't enough for you (sans fearsome giraffes), please take a
    look at our Enterprise or Professional product, which is free for up to 10
    servers. Email us at enterprise@userify.com for details.)"""

    while not password or len(password) < 8:
        password = getpass.getpass("Please provide a STRONG password: ").strip()
    return {"username": username, "password": password}


def questions_signup(data, ssh_only=False):

    data["ssh_public_key"] = ""

    # automatically import SSH public key
    if SSH_PUBLIC_KEY:
        print "\n\nPublic key found in %s" % SSH_KEYDIR
        print "Automatically import your SSH public key?\n(You can update later.)"
        foo = raw_input("\nPress enter to accept or N to reject.").strip().lower()
        if not foo or foo[0] in 'y1to':
            data["ssh_public_key"] = SSH_PUBLIC_KEY

    if ssh_only:
        data["company"] = raw_input("\nPlease provide a company name: ") or "First Company"
        return

    email = company = ""

    while not email:
        email = string_test(raw_input("\nPlease provide a email: "), is_email=True)

    # company, project, server group
    domain = email.split("@")[1].title().split(".")[0]
    if domain.endswith("mail"): domain = ""
    while not company:
        if domain:
            company = raw_input("\nPlease provide a company [%s]: " % domain)
            if not company: company = domain
        else:
            company = raw_input("\nPlease provide a company name: ")

    data.update({ "name": data["username"].title(),
         "email": email, "company": company})


def create_company(api, data):
    name = data["company"] or "First Company"
    print "Creating company %s .." % name
    if "name" in data and "email" in data:
        notes = ("Created by %s <%s>"
         % (data["name"], data["email"]))
    else:
        notes = ""
    response, response_data = api.post("/company",
        {"name": name, "notes": notes})
    company_id = response_data["company_id"]
    return company_id

def check_username(api, username=""):
    # https://dashboard.userify.com/api/userify/username/jamieson
    print "Checking username %s .." % username
    response, response_data = api.get("/username/%s" % username, handle_error=False)
    return response_data and "status" in response_data and response_data["status"] == "success"

def create_project(api, data, name="First Project"):
    print "Creating projects %s .." % name
    response, response_data = api.post(
        "/project/company_id/" + company_id, {"name": name})
    return response_data["project_id"]

def create_servergroup(api, data, project_id, name="First Server Group"):
    print "Creating your first server group %s .." % name
    response, response_data = api.post("/project/company_id/"
        + company_id + "/parent_project_id/" + project_id,
        {"name": name})
    return response_data["project_id"]

# delete 

def delete_company(api, company_id):
    print "Deleting company %s .." % company_id
    return api.delete("/company/company_id/%s" % company_id)

def delete_project(api, company_id, project_id):
    print "Deleting project %s .." % project_id
    return api.delete(
        "/project/company_id/%s/project_id/%s" %
        (company_id, project_id))

# grant root

def grant_root(api, company_id, servergroup_id, user_id):
    response, response_data = api.put("/usergroup/company_id/%s/project_id/%s/usergroup/linux_admins/user_id/%s" %
        (company_id, servergroup_id, user_id), "")

# shim_installer
def get_shim_installer(api, company_id, servergroup_id, name="one_line"):
    response, shim_installer = api.get(
        "/shim_installers/company_id/%s/project_id/%s" % (company_id, servergroup_id))
    return shim_installer[name].strip()

if __name__ == "__main__":

    print "Welcome to Userify!"

    # create API object
    api = API()

    # first, signup user account.
    data = ask_username_password(api)
    auth = None

    print "Creating your user account.."
    response, rdata = api.post("/profile", data, handle_error=False)

    already_in_use = False
    move_on = False

    if response.status != 200:
        if rdata and "error" in rdata:
            error = rdata["error"]
            if response.status == 400 and error == "Username already in use.":
                already_in_use = True
                move_on = True
            if response.status == 400 and error == "Please provide an email address.":
                questions_signup(data, ssh_only=False)
                response, rdata = api.post("/profile", data)
                move_on = True

    if not move_on:
        die(response.reason, error)
    
    # login and verify that getting profile works
    api.login(data["username"], data["password"])
    response, user = api.get("/profile")

    # ask more questions
    if already_in_use:
        questions_signup(data, ssh_only=already_in_use)

    if data["ssh_public_key"]:
        # update profile
        api.put("/profile", data)
    else:
        print "To log in, please update your key at https://dashboard.userify.com"

    data.update({
        "project_name": "First Project",
        "servergroup_name": "First Server Group"})

    # create company
    company_id = create_company(api, data)

    # create project
    project_id = create_project(api, data, data["project_name"])

    # create server group
    servergroup_id = create_servergroup(api, data, project_id, data["servergroup_name"])

    # grant root to self
    grant_root(api, company_id, servergroup_id, user["id"])

    # get the shim installer
    one_liner = get_shim_installer(api, company_id, servergroup_id, "one_line")

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        fn = temp.name
        temp.write("#! /bin/sh\n\n" + one_liner)
        temp.close()
        os.chmod(fn, 0o700)
        qexec(["sudo", fn])
        os.unlink(fn)

    print "Please visit https://dashboard.userify.com "
    print "and log in with the above username (%s) " % data["username"]
    print "and password."
    print
    if not data["ssh_public_key"]:
        print "Don't forget to update your key!"


    # How to cleanup (companies, not user account)
    # wait = raw_input("Roll back just created companies?").strip().lower() 
    # if wait and "y" in wait:
    #     delete_project(api, company_id, servergroup_id)
    #     delete_project(api, company_id, project_id)
    #     delete_company(api, company_id)
    #     qexec(["sudo", "/opt/userify/uninstall.sh"])

