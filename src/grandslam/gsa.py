from base64 import b64encode, b64decode
from datetime import datetime
from random import randbytes
import uuid
import locale
import plistlib as plist
import json
import hashlib
import hmac
import requests
import srp._pysrp as srp
import pbkdf2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import getpass

# Constants
DEBUG = False  # Allows using a proxy for debugging (disables SSL verification)
# Server to use for anisette generation
ANISETTE = "https://sign.rheaa.xyz/"
#ANISETTE = 'http://45.132.246.138:6969/'
#ANISETTE = 'https://sideloadly.io/anisette/irGb3Quww8zrhgqnzmrx'
#ANISETTE = "http://jkcoxson.com:2052/"

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
import urllib3

urllib3.disable_warnings()


def generate_anisette() -> dict:
    r = requests.get(ANISETTE, verify=False if DEBUG else True, timeout=5)
    r = json.loads(r.text)
    return r


class Anisette:
    @staticmethod
    def _fetch(url: str) -> dict:
        """Fetches anisette data that we cannot calculate from a remote server"""
        r = requests.get(url, verify=False if DEBUG else True, timeout=5)
        r = json.loads(r.text)
        return r

    def __init__(self, url: str = ANISETTE, name: str = "") -> None:
        self._name = name
        self._url = url
        self._anisette = self._fetch(self._url)

        # Generate a "user id": just a random UUID
        # TODO: Figure out how to tie it to the user's account on the device
        self._user_id = str(uuid.uuid4()).upper()

    # override string printing
    def __str__(self) -> str:
        return f"{self._name} ({self.backend})"

    @property
    def url(self) -> str:
        return self._url
    
    @property
    def backend(self) -> str:
        if self._anisette["X-MMe-Client-Info"] == "<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>":
            return "AltServer"
        elif self._anisette["X-MMe-Client-Info"] == "<iMac11,3> <Mac OS X;10.15.6;19G2021> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>":
            return "Provision"
        else:
            return f"Unknown ({self._anisette['X-MMe-Client-Info']})"
    
    # Getters
    @property
    def timestamp(self) -> str:
        """'Timestamp'
            Current timestamp in ISO 8601 format
        """

        # We only want sencond precision, so we set the microseconds to 0
        # We also add 'Z' to the end to indicate UTC
        # An alternate way to write this is strftime("%FT%T%zZ")
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    @property
    def timezone(self) -> str:
        """'Time Zone'
            Abbreviation of the timezone of the device (e.g. EST)"""

        return str(datetime.utcnow().astimezone().tzinfo)

    @property
    def locale(self) -> str:
        """'Locale'
            Locale of the device (e.g. en_US)
        """

        return locale.getdefaultlocale()[0] or "en_US"

    @property
    def otp(self) -> str:
        """'One Time Password'
            A seemingly random base64 string containing 28 bytes
            TODO: Figure out how to generate this
        """

        return self._anisette["X-Apple-I-MD"]

    @property
    def local_user(self) -> str:
        """'Local User ID'
            There are 2 possible implementations of this value
            1. Uppercase hex of the SHA256 hash of some unknown value (used by Windows based servers)
            2. Base64 encoding of an uppercase UUID (used by android based servers)
            I picked the second one because it's more fully understood.
        """

        return b64encode(self._user_id.encode()).decode()

    @property
    def machine(self) -> str:
        """'Machine ID'
            This is a base64 encoded string of 60 'random' bytes
            We're not sure how this is generated, we have to rely on the server
            TODO: Figure out how to generate this
        """

        return self._anisette["X-Apple-I-MD-M"]

    @property
    def router(self) -> str:
        """'Routing Info'
            This is a number, either 17106176 or 50660608
            It doesn't seem to matter which one we use,
            17106176 is used by Sideloadly and Provision (android) based servers
            50660608 is used by Windows iCloud based servers
        """

        return '17106176'

    @property
    def serial(self) -> str:
        """'Device Serial Number'
            This is the serial number of the device
            You can use a legitimate serial number, but Apple accepts '0' as well (for andriod devices)
            See https://github.com/acidanthera/OpenCorePkg/blob/master/Utilities/macserial/macserial.c for how to generate a legit serial
        """

        return '0'

    @property
    def device(self) -> str:
        #print(self._anisette["X-Mme-Device-Id"])
        return self._anisette["X-Mme-Device-Id"]

    @property
    def client(self) -> str:
        return self._anisette["X-MMe-Client-Info"]

    def generate_headers(self, client_info: bool = False) -> dict:
        h = {
            # Current Time
            "X-Apple-I-Client-Time": self.timestamp,
            "X-Apple-I-TimeZone": self.timezone,
            # Locale
            # Some implementations only use this for locale
            "loc": self.locale,
            "X-Apple-Locale": self.locale,
            # Anisette
            "X-Apple-I-MD": self.otp,  # 'One Time Password'
            # 'Local User ID'
            "X-Apple-I-MD-LU": self.local_user,
            "X-Apple-I-MD-M": self.machine,  # 'Machine ID'
            # 'Routing Info', some implementations convert this to an integer
            "X-Apple-I-MD-RINFO": self.router,
            # Device information
            # 'Device Unique Identifier'
            "X-Mme-Device-Id": self.device,
            # 'Device Serial Number'
            "X-Apple-I-SRL-NO": self.serial,
        }

        # Additional client information only used in some requests
        if client_info:
            h["X-Mme-Client-Info"] = self.client
            h["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
            h["X-Xcode-Version"] = "11.2 (11B41)"

        return h

    def generate_cpd(self) -> dict:
        cpd = {
            # Many of these values are not strictly necessary, but may be tracked by Apple
            # I've chosen to match the AltServer implementation
            # Not sure what these are for, needs some investigation
            "bootstrap": True,  # All implementations set this to true
            "icscrec": True,  # Only AltServer sets this to true
            "pbe": False,  # All implementations explicitly set this to false
            "prkgen": True,  # I've also seen ckgen
            "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
            # Not included, but I've also seen:
            # 'capp': 'AppStore',
            # 'dc': '#d4c5b3',
            # 'dec': '#e1e4e3',
            # 'prtn': 'ME349',
        }

        cpd.update(self.generate_headers())
        return cpd


def authenticated_request(parameters, anisette: Anisette) -> dict:
    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": anisette.generate_cpd(),
        },
    }
    body["Request"].update(parameters)
    # print(plist.dumps(body).decode('utf-8'))

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": anisette.client,
    }

    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,  # TODO: Verify Apple's self-signed cert
        timeout=5,
    )

    return plist.loads(resp.content)["Response"]


def check_error(r):
    # Check for an error code
    if "Status" in r:
        status = r["Status"]
    else:
        status = r

    if status["ec"] != 0:
        print(f"Error {status['ec']}: {status['em']}")
        return True
    return False


def encrypt_password(password: str, salt: bytes, iterations: int) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, hashlib.sha256).read(32)


def create_session_key(usr: srp.User, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def decrypt_cbc(usr: srp.User, data: bytes) -> bytes:
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


def trusted_second_factor(dsid, idms_token, anisette: Anisette):
    identity_token = b64encode((dsid + ":" + idms_token).encode()).decode()
    
    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
    }

    headers.update(anisette.generate_headers(client_info=True))

    # This will trigger the 2FA prompt on trusted devices
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    requests.get(
        "https://gsa.apple.com/auth/verify/trusteddevice",
        headers=headers,
        verify=False,
        timeout=10,
    )

    # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
    code = getpass.getpass("Enter 2FA code: ")
    #code = input("Enter 2FA code: ")
    headers["security-code"] = code

    # Send the 2FA code to Apple
    resp = requests.get(
        "https://gsa.apple.com/grandslam/GsService2/validate",
        headers=headers,
        verify=False,
        timeout=10,
    )
    r = plist.loads(resp.content)
    if check_error(r):
        return

    print("2FA successful")

def sms_second_factor(dsid, idms_token, anisette: Anisette):
    identity_token = b64encode((dsid + ":" + idms_token).encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        #"Accept": "text/x-xml-plist",
        "Accept": "application/x-buddyml",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
    }

    headers.update(anisette.generate_headers(client_info=True))

    body = {
        "serverInfo": {
            "phoneNumber.id": "1"
        }   
    }

    # This will send the 2FA code to the user's phone over SMS
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    requests.post(
        "https://gsa.apple.com/auth/verify/phone/put?mode=sms",
        data=plist.dumps(body),
        headers=headers,
        verify=False,
        timeout=5,
    )

    # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
    code = input("Enter 2FA code: ")

    body = {
        "securityCode.code": code,
        "serverInfo": {
            "mode": "sms",
            "phoneNumber.id": "1"
        }
    }
    #headers["security-code"] = code

    # Send the 2FA code to Apple
    resp = requests.post(
        "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put",
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=5,
    )
    print(resp.content.decode())
    #r = plist.loads(resp.content)
    #if check_error(r):
    #    return

    #print("2FA successful")


def authenticate(username, password, anisette: Anisette):

    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()

    r = authenticated_request(
        {
            "A2k": A,
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        },
        anisette,
    )

    # Check for an error code
    if check_error(r):
        return

    if r["sp"] != "s2k":
        print(f"This implementation only supports s2k. Server returned {r['sp']}")
        return

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"])  # type: ignore

    M = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if M is None:
        print("Failed to process challenge")
        return

    r = authenticated_request(
        {
            "c": r["c"],
            "M1": M,
            "u": username,
            "o": "complete",
        },
        anisette,
    )

    if check_error(r):
        return

    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        print("Failed to verify session")
        return

    spd = decrypt_cbc(usr, r["spd"])
    # For some reason plistlib doesn't accept it without the header...
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)

    if "au" in r["Status"] and r["Status"]["au"] == "trustedDeviceSecondaryAuth":
        print("Trusted device authentication required")
        trusted_second_factor(spd["adsid"], spd["GsIdmsToken"], anisette)
    elif "au" in r["Status"] and r["Status"]["au"] == "secondaryAuth":
        print("SMS authentication required")
        sms_second_factor(spd["adsid"], spd["GsIdmsToken"], anisette)
    elif "au" in r["Status"]:
        print(f"Unknown auth value {r['Status']['au']}")
        return
    else:
        print("Assuming 2FA is not required")
        