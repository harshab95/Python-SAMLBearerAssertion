from __future__ import absolute_import, division, print_function, unicode_literals
import xmlsec
from lxml import etree
import pytz
from datetime import datetime, timedelta
#import cStringIO


def generate_assertion(sf_root_url, user_id, client_id,audience):
    issue_instant = datetime.utcnow().replace(tzinfo=pytz.utc)
    auth_instant = issue_instant
    not_valid_before = issue_instant - timedelta(minutes=10)
    not_valid_after = issue_instant + timedelta(minutes=10)

    #audience = 'www.successfactors.com'
    public_key = """MIIDWTCCAkGgAwIBAgIEBXHy+TANBgkqhkiG9w0BAQsFADBdMQswCQYDVQQGEwJJ
TjELMAkGA1UECBMCTUgxCzAJBgNVBAcTAk5NMQwwCgYDVQQKEwNSSUwxCzAJBgNV
BAsTAklUMRkwFwYDVQQDExBwZHdzbzJtMS5yaWwuY29tMB4XDTE5MDkxNjA1NTMy
MloXDTQ3MDIwMTA1NTMyMlowXTELMAkGA1UEBhMCSU4xCzAJBgNVBAgTAk1IMQsw
CQYDVQQHEwJOTTEMMAoGA1UEChMDUklMMQswCQYDVQQLEwJJVDEZMBcGA1UEAxMQ
cGR3c28ybTEucmlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKi5qVpL/gigvmrF36aObRjLfcdLla+c0vect33dxPqLN361SGHt4H0DfrShZ80M
1qJ8L3bn0cSIq9INYA8mnvda5PPdw8sDEdZnASmAnMz0py8MfDcSjfqjg5RcwJ6Z
WaBVmo4aZXYwFoqODVCNfDw3sHCxrVkiC4w6orDgj+QgI9rKmXwzKKg2kyvj1DTZ
//LSuIkEDXISumlcdkrsy7bOdYXPsV/O5ph57DH9yCeq1Vq+PXREkSiiulDkwr8D
IgbT4m0PzSNnCtyEjyyrIr8b0J2REWs1yAiyEdGPrs+XB2RbSHgI6QVLV/A5ImxW
a3SHPkgfetQXbV1Pg+vmudMCAwEAAaMhMB8wHQYDVR0OBBYEFC3imQgM/VC50W+S
hgQx0uvNq/2eMA0GCSqGSIb3DQEBCwUAA4IBAQA+8yi1Sa7Zd5F5IiYOjH3cH1RF
+vfMP53OMNGyG90lcW//hCx0cyxzDcihtQGThzXLH8f/Eg3OL3gdw9cByCpFx8sZ
8l6Oo0pn09wxYwjaTjhNTD9QV5Z6SR3FJm1GLuW2HOprpw75Q1o6GE6eci9f/dH/
xecFfMlGR2s5M599ZtgPvrQWeO9YCI6zvF2y74I0TfMe/klovn5F5eQUxSrtGAb6
+5ayp9zIflsG05RlmRhTaMhUIG/3MdleUmKWMn2+32vmsFgyZZts+ZR9dRQCaTXT
JOQmKvk3di38omJ0zdApCufp5nT1H/G+wlPKU9YEokncEQACSfWWXjv4tzjy"""
    context = dict(
        issue_instant=issue_instant.isoformat(),
        auth_instant=auth_instant.isoformat(),
        not_valid_before=not_valid_before.isoformat(),
        not_valid_after=not_valid_after.isoformat(),
        sf_root_url=sf_root_url,
        audience=audience,
        user_id=user_id,
        client_id=client_id,
        session_id='mock_session_index',
        public_key = public_key
    )

    return SAML_ASSERTION_TEMPLATE.format(**context)


def sign_assertion(xml_string):

    key = xmlsec.Key.from_file("/Users/macbug/Desktop/wso2carbon.pem", xmlsec.KeyFormat.PEM)
    root = etree.fromstring(text = xml_string)
    signature_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)
    print(etree.tostring(signature_node))
    sign_context = xmlsec.SignatureContext()
    sign_context.key = key
    sign_context.sign(signature_node)

    return etree.tostring(root)


SAML_ASSERTION_TEMPLATE = """
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mfkbinfpcpcaeokkbmidmklnmbmfdelnhbkffmei" IssueInstant="{issue_instant}" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{client_id}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" /><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><ds:Reference URI="#mfkbinfpcpcaeokkbmidmklnmbmfdelnhbkffmei"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/20001/10/xml-exc-c14n#"/><ec:InclusiveNamespaces xmlns:ec="http://w3.org/2001/10/xml-exc-c14n#" PrefixList="ds saml xs xsi"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{public_key}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user_id}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="0" NotOnOrAfter="{not_valid_after}" Recipient="{sf_root_url}/oauth2/token" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{not_valid_before}"  NotOnOrAfter="{not_valid_after}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{issue_instant}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="."><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">.</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>
"""


if __name__ == '__main__':
    unsigned_assertion = generate_assertion("https://sso.ril.com/mysso/saml", "harshavardhan.bugata@ril.com", "apimhc.ril.com", "https://apimhc.ril.com:9443/oauth2/token")
    print(str(sign_assertion(unsigned_assertion)))
