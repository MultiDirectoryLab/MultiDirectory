"""Datasets for testing API."""

test_api_whitespaces_in_attr_value =[
    {
        "entry": "cn=\20test ,test,dc=md,dc=test",
    },
    {
        "entry": "cn= test\20,test,dc=md,dc=test",
    },
    {
        "entry": "cn=\20test\20,test,dc=md,dc=test",
    },
    {
        "entry": "cn= test ,test,dc=md,dc=test",
    },
    {
        "entry": "cn=\20test,test,dc=md,dc=test",
    },
    {
        "entry": "cn=test\20,test,dc=md,dc=test",
    },
    {
        "entry": "cn= test,test,dc=md,dc=test",
    },
    {
        "entry": "cn=test ,test,dc=md,dc=test",
    },
]
