# Mutation table for hanzoai/idv, scored by cloud's scripts/mutate.py (strict: a
# mutant that does not compile, whose anchor drifted, or whose -run matched nothing
# is a hard FAILURE, never a kill).
#
#   MUTATE_ROOT=<idv tree> MUTATE_TABLE=<this file> <cloud>/scripts/mutate.py [filter]
#
# Two properties, both about not manufacturing a verdict:
#   a webhook is read only after it is proven to come from the provider, and
#   a provider that does not parse the response reports no decision.

W = "provider/webhook.go"
O = "provider/onfido.go"
L = "provider/lexisnexis.go"
I = "provider/intellicheck.go"
P = "./provider/"

MUTANTS = [
    # An empty secret makes the HMAC computable by anyone, so "verifying" against it
    # admits any forged verdict. Skipping the refusal is the plausible bug.
    ("idv: an empty webhook secret is allowed to verify", [
        (W, 'if secret == "" || signature == "" {',
            'if signature == "" {')],
     "TestProviderWebhookAuth", P),

    # The comparison itself. If it always matches, every tampered body is accepted.
    # (Comparing against a constant false leaves `got` unused, which does not
    # compile — and a NO-COMPILE is not a kill — so the digest is compared with
    # itself instead: same always-matches effect, still typechecks.)
    ("idv: the signature comparison always matches", [
        (W, "if !hmac.Equal(got, mac.Sum(nil)) {",
            "if !hmac.Equal(got, got) {")],
     "TestProviderWebhookAuth", P),

    # Onfido's verification, absent until now: decode without proving the sender.
    ("idv: onfido decodes a webhook without verifying it", [
        (O, '\tif err := verifyHMAC(body, o.cfg.WebhookToken, header(headers, "X-SHA2-Signature")); err != nil {\n\t\treturn nil, err\n\t}\n',
            "")],
     "TestProviderWebhookAuth", P),

    # The auto-approve that was live in both LexisNexis entry points and in
    # Intellicheck's. Each of these restores a pass the provider never gave.
    ("idv: lexisnexis check synthesizes an approval", [
        (L, 'return nil, fmt.Errorf("lexisnexis: no verdict is parsed — status cannot be reported")',
            "return &VerificationStatusResult{Status: StatusApproved}, nil")],
     "TestUnreadCheckRefuses|TestInitiateIsNeverApproved", P),

    ("idv: lexisnexis initiate synthesizes an approval", [
        (L, 'return nil, fmt.Errorf("lexisnexis: the FlexID response carries the verdict and is not parsed — no decision can be reported")',
            "return &VerificationResponse{Provider: ProviderLexisNexis, Status: StatusApproved}, nil")],
     "TestUnreadCheckRefuses|TestInitiateIsNeverApproved", P),

    ("idv: intellicheck check synthesizes an approval", [
        (I, 'return nil, fmt.Errorf("intellicheck: the results response is not parsed — no decision can be reported")',
            "return &VerificationStatusResult{Status: StatusApproved}, nil")],
     "TestUnreadCheckRefuses|TestInitiateIsNeverApproved", P),
]
