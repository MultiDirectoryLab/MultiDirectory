"""Datasets for testing API."""

test_api_whitespaces_in_attr_value = [
    {
        "entry": "cn=\x20test ,dc=md,dc=test",
    },
    {
        "entry": "cn= test\x20,dc=md,dc=test",
    },
    {
        "entry": "cn=\x20test\x20,dc=md,dc=test",
    },
    {
        "entry": "cn= test ,dc=md,dc=test",
    },
    {
        "entry": "cn=\x20test,dc=md,dc=test",
    },
    {
        "entry": "cn=test\x20,dc=md,dc=test",
    },
    {
        "entry": "cn= test,dc=md,dc=test",
    },
    {
        "entry": "cn=test ,dc=md,dc=test",
    },
]
