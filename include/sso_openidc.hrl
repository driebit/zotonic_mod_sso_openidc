-record(sso_openidc_configuration_get, {}).

-record(sso_openidc_configuration, {
    issuers :: list()
}).

-record(sso_openidc_identity_props, {
    provider :: atom(),
    claims = #{} :: map(),
    user_info = #{} :: map(),
    person_props = #{} :: map()
}).
