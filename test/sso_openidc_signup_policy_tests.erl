-module(sso_openidc_signup_policy_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("zotonic_core/include/zotonic.hrl").

testprovider_policy_test() ->
    meck:new(z_context, [passthrough, no_link]),
    try
        meck:expect(z_context, hostname, fun(_) -> <<"localhost">> end),
        {ok, Provider} = m_sso_openidc:find_by_name(testprovider, #context{}),
        ?assertEqual(false, mod_sso_openidc:provider_add_username_pw(Provider))
    after
        meck:unload(z_context)
    end.
