from django.shortcuts import render

from datetime import datetime
from saml import schema

from onelogin.saml2 import utils

saml2_utils = utils.OneLogin_Saml2_Utils()

# Create your views here.
def create_document():
    document = schema.Response()
    document.id = '11111111-1111-1111-1111-111111111111'
    document.in_response_to = '22222222-2222-2222-2222-222222222222'
    document.issue_instant = datetime(2000, 1, 1, 1)
    document.issuer = 'https://idp.example.org/SAML2'
    document.destination = 'https://sp.example.com/SAML2/SSO/POST'
    document.status.code.value = schema.StatusCode.SUCCESS
    return document

def create_assertion(document):
    document.assertions = assertion = schema.Assertion()
    assertion.id = '33333333-3333-3333-3333-333333333333'
    assertion.issue_instant = datetime(2000, 1, 1, 2)
    assertion.issuer = 'https://idp.example.org/SAML2'
    return assertion

def create_subject(assertion):
    assertion.subject = schema.Subject()
    assertion.subject.principal = '44444444-4444-4444-4444-444444444444'
    assertion.subject.principal.format = schema.NameID.Format.TRANSIENT
    data = schema.SubjectConfirmationData()
    data.in_response_to = '22222222-2222-2222-2222-222222222222'
    data.not_on_or_after = datetime(2000, 1, 1, 1, 10)
    data.recipient = 'https://sp.example.com/SAML2/SSO/POST'
    confirmation = schema.SubjectConfirmation()
    confirmation.data = data
    assertion.subject.confirmation = confirmation
    return data

def create_auth_statement(assertion):
    statement = schema.AuthenticationStatement()
    assertion.statements.append(statement)
    statement.authn_instant = datetime(2000, 1, 1, 1, 3)
    statement.session_index = '33333333-3333-3333-3333-333333333333'
    reference = schema.AuthenticationContextReference
    statement.context.reference = reference.PASSWORD_PROTECTED_TRANSPORT
    return statement, reference

def create_auth_condition(assertion):
    assertion.conditions = conditions = schema.Conditions()
    conditions.not_before = datetime(2000, 1, 1, 1, 3)
    conditions.not_on_or_after = datetime(2000, 1, 1, 1, 9)
    condition = schema.AudienceRestriction()
    condition.audiences = 'https://sp.example.com/SAML2'
    conditions.condition = condition
    return conditions

def create_saml_response():

    document = create_document()
    assertion = create_assertion(document)
    data = create_subject(assertion)
    statement, reference = create_auth_statement(assertion)
    conditions = create_auth_condition(assertion)

    return document.tostring()

def home(request):
    saml_response = create_saml_response()
    context = {
        'deflated_and_base64_encoded_saml_response': saml2_utils.deflate_and_base64_encode(saml_response),
        'saml_response': saml_response,
    }
    return render(request, 'home.html', context)
