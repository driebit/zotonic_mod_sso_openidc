%% @author Driebit BV <tech@driebit.nl>
%% @copyright 2025-2026 Driebit BV
%% @doc Module for Single Sign-On via OpenID Connect. This module allows you to configure
%% one or more OpenID Connect providers that can be used for Single Sign-On. It provides
%% a separate worker for each provider that manages the OIDC configuration and can be used
%% to fetch the OIDC configuration and JWKS from the provider. The module intercepts
%% logons and checks if the user has an email address or username matching the domain of a
%% configured provider and if so, forces the user to log in via that provider. It provides
%% an admin interface to manage the configured providers.
%%
%% The module is a supervisor with a separate worker for each configured provider.
%% @end

%% Copyright 2024-2026 Driebit BV
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(mod_sso_openidc).
-author("Driebit <tech@driebit.nl>").

-mod_title("SSO OpenID Connect").
-mod_description("Authentication and Single Sign-On via OpenID Connect").
-mod_prio(200).
-mod_depends([mod_authentication]).
-mod_provides([sso_openidc]).
-mod_schema(2).

-behaviour(supervisor).

-export([
    event/2,
    observe_admin_menu/3,
    observe_auth_identity_types/3,

    observe_logon_options/3,
    observe_auth_postcheck/2,

    scopes/1,
    return_url/1,
    organisations_for_provider/2,
    is_known_provider/2,
    local_provider_names/2,
    provider_by_name/2,
    provider_name/1,
    provider_credentials/1,
    provider_has_userinfo/1,
    provider_email_required/1,
    provider_email_verified/1,
    provider_add_username_pw/1,
    provider_is_mfa/1,
    provider_acr_values/1,
    is_mfa_acr/1,
    provider_organizations/1,
    ensure_provider/2,
    maybe_reload_provider/2,
    stop_provider/2,
    get_provider_configuration/2,
    fetch_provider_configuration/2,
    manage_schema/2,
    manage_data/2
]).

-export([
    init/1,
    start_link/1
]).


-include_lib("zotonic_core/include/zotonic.hrl").
-include_lib("zotonic_mod_admin/include/admin_menu.hrl").

%% Maximum allowed difference in clocks between our server and the
%% OOIDC provider's server. In seconds.
-define(MAX_CLOCK_SKEW, 300).

-type provider_name() :: atom().
-type acr_value() :: binary() | string().
-type provider() :: #{
        is_enabled := boolean(),
        is_test_server := boolean(),
        is_retrieve_userinfo := boolean(),
        is_email_required := boolean(),
        is_email_verified := boolean(),
        has_userinfo := boolean(),
        name := provider_name(),
        domain := binary(),
        description => binary(),
        issuer_url => binary(),
        logo_url => binary(),
        client_id := binary(),
        client_secret := binary(),
        grant_type => binary(),
        organizations => [ binary() ],
        request_scopes => [ binary() ],
        acr_values => [ acr_value() ]
    }.

-export_type([
    provider_name/0,
    acr_value/0,
    provider/0
]).

event(#submit{ message={oidc_provider_insert, Args} }, Context) ->
    case m_sso_openidc:is_authorized(Context) of
        true ->
            Name = z_context:get_q_validated(<<"name">>, Context),
            Domain = z_context:get_q_validated(<<"domain">>, Context),
            case m_sso_openidc:insert(Name, Domain, Context) of
                {ok, AppId} ->
                    Context1 = z_render:update(
                        "oidc-providers-list",
                        #render{
                            template = "_admin_oidc_providers_list.tpl",
                            vars = []
                        },
                        Context),
                    z_render:dialog(
                        ?__("Edit OpenID provider details", Context),
                        "_dialog_oidc_provider.tpl",
                        [ {app_id, AppId}, {is_new, true} ],
                        Context1);
                {error, duplicate_name} ->
                    Context1 = z_render:wire(proplists:get_value(onname_error, Args), Context),
                    z_render:growl_error(?__("An OpenID provider with this name already exists, please use another name.", Context1), Context1);
                {error, oidc_config} ->
                    Context1 = z_render:wire(proplists:get_value(ondomain_error, Args), Context),
                    z_render:growl_error(?__("Could not fetch the OpenID configuration from the domain.", Context1), Context1);
                {error, _} ->
                    z_render:growl_error(?__("Could not insert the OpenID provider.", Context), Context)
            end;
        false ->
            z_render:growl_error(?__("You are not allowed to change OpenID provider.", Context), Context)
    end;
event(#submit{ message={oidc_provider_update, [ {app_id, AppId} ]} }, Context) ->
    case m_sso_openidc:is_authorized(Context) of
        true ->
            Provider = qprovider(Context),
            case m_sso_openidc:update(AppId, Provider, Context) of
                ok ->
                    z_render:wire({redirect, [ {dispatch, admin_oidc_providers} ]}, Context);
                {error, _} ->
                    z_render:growl_error(?__("Could not update the OpenID provider.", Context), Context)
            end;
        false ->
            z_render:growl_error(?__("You are not allowed to change OpenID provider.", Context), Context)
    end;
event(#postback{ message={oidc_provider_delete, [ {app_id, AppId} ]} }, Context) ->
    case m_sso_openidc:is_authorized(Context) of
        true ->
            case m_sso_openidc:delete(AppId, Context) of
                ok ->
                    z_render:wire({redirect, [ {dispatch, admin_oidc_providers} ]}, Context);
                {error, _} ->
                    z_render:growl_error(?__("Could not insert the OpenID provider.", Context), Context)
            end;
        false ->
            z_render:growl_error(?__("You are not allowed to change OpenID provider.", Context), Context)
    end.

observe_admin_menu(#admin_menu{}, Acc, Context) ->
     [
         #menu_item{
            id = admin_oidc_providers,
            parent = admin_auth,
            label = ?__("OpenID Connect Providers", Context),
            url = {admin_oidc_providers, []},
            visiblecheck = {acl, use, mod_sso_openidc},
            sort = 1
        }
        | Acc
    ].

%% @doc Tell the identity model that identities belonging to this module can make somebody an user.
%% Also add 'openid' for compatibility with a previous openid module.
%% This is needed to be able to match users by verified email address.
observe_auth_identity_types(#auth_identity_types{ type = user }, Types, _Context) ->
    [ ?MODULE, openid | Types ];
observe_auth_identity_types(#auth_identity_types{ type = _ }, Types, _Context) ->
    Types.


%% @doc Pre-check on the two-step logon, Check if the user has an username or primary
%% email address domain that is controlled by an OpenIDC provider.
observe_logon_options(#logon_options{
            payload = #{
                <<"username">> := Username,
                <<"password">> := undefined
            }
        },
        Acc,
        Context) when is_binary(Username) ->
    case providers_for_username(Username, Context) of
        [] ->
            Acc;
        Ps ->
            Acc#{
                is_username_checked => true,
                is_user_external => true,
                is_user_local => false,
                user_external => [
                    #{
                        template => <<"_oidc_logon_external.tpl">>,
                        apps => Ps
                    }
                ]
            }
    end;
observe_logon_options(#logon_options{}, Acc, _Context) ->
    Acc.

%% @doc Check if the given user is using a controlled domain to logon or has a
%% controlled domain as their primary email address.
providers_for_username(Username, Context) ->
    case binary:match(Username, <<"@">>) =/= nomatch of
        true ->
            case providers_for_domain(Username, Context) of
                [] ->
                    providers_for_username_1(Username, Context);
                Ps ->
                    Ps
            end;
        false ->
            providers_for_username_1(Username, Context)
    end.

providers_for_username_1(Username, Context) ->
    case m_identity:lookup_by_type_and_key_multi(username_pw, Username, Context) of
        [] -> [];
        Idns ->
            Found = lists:filtermap(
                fun(Idn) ->
                    RscId = proplists:get_value(rsc_id, Idn),
                    Email = m_rsc:p_no_acl(RscId, <<"email_raw">>, Context),
                    case providers_for_domain(Email, Context) of
                        [] -> false;
                        Ps -> {true, Ps}
                    end
                end,
                Idns),
            lists:flatten(Found)
    end.

%% @doc Intercept logons for users that have a primary email address matching the
%% controlled domains of an OpenIDC provider. They should use the OIDC provider to log in.
observe_auth_postcheck(#auth_postcheck{ id = Id }, Context) ->
    Email = m_rsc:p_no_acl(Id, <<"email_raw">>, Context),
    case providers_for_domain(Email, Context) of
        [] -> undefined;
        _Ps -> {error, user_external}
    end.

providers_for_domain(undefined, _Context) ->
    [];
providers_for_domain(<<>>, _Context) ->
    [];
providers_for_domain(EmailOrDomain, Context) ->
    Domain = lists:last(binary:split(EmailOrDomain, <<"@">>, [ global, trim_all ])),
    {ok, Providers} = m_sso_openidc:list_providers_for_domain(Domain, Context),
    Providers.

%% @doc Fetch the updateable properties of the provider edit form.
%% The issuer_url, domain and name can not be changed.
qprovider(Context) ->
    #{
        is_enabled => z_convert:to_bool(z_context:get_q(<<"is_enabled">>, Context)),
        is_use_auth => z_convert:to_bool(z_context:get_q(<<"is_use_auth">>, Context)),
        is_use_import => z_convert:to_bool(z_context:get_q(<<"is_use_import">>, Context)),
        is_test_server => z_convert:to_bool(z_context:get_q(<<"is_test_server">>, Context)),
        is_email_required => z_convert:to_bool(z_context:get_q(<<"is_email_required">>, Context)),
        is_email_verified => z_convert:to_bool(z_context:get_q(<<"is_email_verified">>, Context)),
        is_add_username_pw => z_convert:to_bool(z_context:get_q(<<"is_add_username_pw">>, Context)),
        has_userinfo => z_convert:to_bool(z_context:get_q(<<"has_userinfo">>, Context)),
        priority => case z_convert:to_integer(z_context:get_q(<<"priority">>, Context)) of
                        undefined -> 99;
                        N -> N
                    end,
        description => z_string:trim(z_context:get_q_validated(<<"description">>, Context)),
        logo_url => z_html:sanitize_uri(z_string:trim(z_context:get_q(<<"logo_url">>, Context))),
        client_id => z_string:trim(z_context:get_q_validated(<<"client_id">>, Context)),
        client_secret => z_string:trim(z_context:get_q_validated(<<"client_secret">>, Context)),
        grant_type => z_string:trim(z_context:get_q(<<"grant_type">>, Context)),
        organizations => q_binary_list(<<"organizations">>, Context),
        domains => q_binary_list(<<"domains">>, Context),
        request_scopes => z_context:get_q_all(<<"request_scopes[]">>, Context),
        acr_values => z_context:get_q_all(<<"acr_values[]">>, Context),
        category_id => z_convert:to_integer(z_context:get_q(<<"category_id">>, Context))
    }.

q_binary_list(Arg, Context) ->
    binary:split(
            z_string:to_lower(z_string:trim(z_context:get_q(Arg, Context, <<>>))),
            [ <<",">>, <<";">>, <<" ">>, <<"\n">> ],
            [ global, trim_all ]).


start_link(Args) ->
    supervisor:start_link(?MODULE, Args).

init(Args) ->
    {context, Context} = proplists:lookup(context, Args),
    application:set_env(oidcc, max_clock_skew, ?MAX_CLOCK_SKEW),
    {ok, Apps} = m_sso_openidc:list(Context),
    Workers = lists:filtermap(
        fun
            (#{ name := ProviderName, is_enabled := true } = Provider) ->
                {LocalWorkerName, LocalConfigName} = local_provider_names(ProviderName, Context),
                {true, worker_spec(LocalConfigName, LocalWorkerName, Provider)};
            (#{ is_enabled := false }) ->
                false
        end,
        Apps),
    ?LOG_INFO(#{
        in => zotonic_mod_sso_openidc,
        text => <<"Starting OIDC workers for all configured providers">>,
        count => length(Workers)
    }),
    {ok,{
        #{
            strategy => one_for_one,
            intensity => 20,
            period => 10
        },
        Workers
    }}.

-spec return_url(Context) -> Url when
    Context :: z:context(),
    Url :: binary().
return_url(Context) ->
    ContextNoLang = z_context:set_language('x-default', Context),
    z_context:abs_url(z_dispatcher:url_for(oauth2_service_redirect, ContextNoLang), Context).

organisations_for_provider(_, _Context) ->
    [].

-spec is_known_provider(Provider, Context) -> boolean() when
    Provider :: binary(),
    Context :: z:context().
is_known_provider(Name, Context) ->
    case m_sso_openidc:find_by_name(Name, Context) of
        {ok, _} -> true;
        {error, _} -> false
    end.

-spec provider_by_name(ProviderName, Context) -> Provider when
    ProviderName :: atom() | binary(),
    Context :: z:context(),
    Provider :: provider().
provider_by_name(Name, Context) ->
    {ok, P} = m_sso_openidc:find_by_name(Name, Context),
    P.

%% @doc Ensure that the OIDC worker is started for the given provider.
%% We start a separate worker per site, with unique name for the site.
-spec ensure_provider(Name, Context) -> {ok, WorkerName} | {error, Reason} when
    Name :: atom() | binary(),
    Context :: z:context(),
    WorkerName :: atom(),
    Reason :: enoent | term().
ensure_provider(Name, Context) ->
    case m_sso_openidc:find_by_name(Name, Context) of
        {ok, #{ name := ProviderName } = Provider} ->
            {LocalWorkerName, LocalConfigName} = local_provider_names(ProviderName, Context),
            case erlang:whereis(LocalWorkerName) of
                undefined ->
                    Worker = worker_spec(LocalConfigName, LocalWorkerName, Provider),
                    {ok, SupPid} = z_module_manager:whereis(?MODULE, Context),
                    case supervisor:start_child(SupPid, Worker) of
                        {ok, _} ->
                            {ok, LocalWorkerName};
                        {ok, _, _} ->
                            {ok, LocalWorkerName};
                        {error, {already_started, _}} ->
                            {ok, LocalWorkerName};
                        {error, not_running} ->
                            ?LOG_ERROR(#{
                                in => zotonic_mod_sso_openidc,
                                text => <<"OIDC worker present but not running (crashed?)">>,
                                result => error,
                                reason => not_running,
                                provider_name => ProviderName,
                                provider_config_name => LocalConfigName,
                                provider_worker_name => LocalWorkerName
                            }),
                            supervisor:delete_child(SupPid, LocalConfigName),
                            ensure_provider(Name, Context);
                        {error, _} = Error ->
                            Error
                    end;
                Pid when is_pid(Pid) ->
                    {ok, LocalWorkerName}
            end;
        {error, _} = Error ->
            Error
    end.

worker_spec(LocalConfigName, LocalWorkerName, Provider) ->
    #{
        id => LocalConfigName,
        start => {
            oidcc_provider_configuration_worker,
            start_link,
            [
                #{
                    issuer => maps:get(issuer_url, Provider),
                    name => {local, LocalWorkerName}
                }
            ]
        },
        shutdown => brutal_kill,
        type => worker,
        restart => temporary,
        modules => [ oidcc_provider_configuration_worker ]
    }.

%% @doc After a provider's config is change we might want to reload the configs
%% in the provider. We do this by stopping the provider (if running) and then
%% restart it using ensure_provider/2.
-spec maybe_reload_provider(Name, Context) -> {ok, WorkerName} | {error, Reason} when
    Name :: atom() | binary(),
    Context :: z:context(),
    WorkerName :: atom(),
    Reason :: enoent | term().
maybe_reload_provider(Name, Context) ->
    case stop_provider(Name, Context) of
        ok ->
            ensure_provider(Name, Context);
        {error, _} = Error ->
            Error
    end.

%% @doc Stop the OIDC worker for the given provider (if any).
-spec stop_provider(Name, Context) -> ok | {error, Reason} when
    Name :: atom() | binary(),
    Context :: z:context(),
    Reason :: enoent | term().
stop_provider(Name, Context) ->
    case m_sso_openidc:find_by_name(Name, Context) of
        {ok, #{ name := ProviderName }} ->
            {_LocalWorkerName, LocalConfigName} = local_provider_names(ProviderName, Context),
            {ok, SupPid} = z_module_manager:whereis(?MODULE, Context),
            case stop_and_delete_child(SupPid, LocalConfigName) of
                ok ->
                    ok;
                {error, not_found} ->
                    ok;
                {error, Reason} = Error ->
                    ?LOG_WARNING(#{
                        in => zotonic_mod_sso_openidc,
                        text => <<"Error stopping OIDC configuration worker">>,
                        result => error,
                        reason => Reason,
                        name => Name,
                        config_name => LocalConfigName
                    }),
                    Error
            end;
        {error, Reason} = Error ->
            ?LOG_WARNING(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Error stopping OIDC configuration worker">>,
                result => error,
                reason => Reason,
                name => Name
            }),
            Error
    end.

stop_and_delete_child(Sup, Child) ->
    case supervisor:terminate_child(Sup, Child) of
        ok ->
            supervisor:delete_child(Sup, Child);
        {error, not_found} ->
            ok;
        {error, _} = Error ->
            Error
    end.

%% @doc Fetch the configuration for the given provider. Fetches it either from the
%% provider configurarion worker or the well-known URL at the domain.
-spec get_provider_configuration(Name, Context) -> {ok, Config} | {error, Reason} when
    Name :: atom() | binary(),
    Context :: z:context(),
    Config :: oidcc_provider_configuration:t(),
    Reason :: enoent | term().
get_provider_configuration(Name, Context) ->
    case m_sso_openidc:find_by_name(Name, Context) of
        {ok, #{ name := ProviderName, domain := Domain, is_enabled := true }} ->
            try
                {LocalWorkerName, _LocalConfigName} = local_provider_names(ProviderName, Context),
                case erlang:whereis(LocalWorkerName) of
                    undefined ->
                        fetch_provider_configuration(Domain, Context);
                    Pid when is_pid(Pid) ->
                        {ok, oidcc_provider_configuration_worker:get_provider_configuration(Pid)}
                end
            catch
                _:_ ->
                    fetch_provider_configuration(Domain, Context)
            end;
        {ok, #{ domain := Domain }} ->
            fetch_provider_configuration(Domain, Context);
        {error, _} = Error ->
            Error
    end.

%% @doc Fetch the OIDC configuration at the well-known URL of the given domain.
-spec fetch_provider_configuration(Domain, Context) -> {ok, Config} | {error, Reason} when
    Domain :: binary() | string(),
    Context :: z:context(),
    Config :: oidcc_provider_configuration:t(),
    Reason :: term().
fetch_provider_configuration(<<>>, _Context) ->
    {error, domain};
fetch_provider_configuration("", _Context) ->
    {error, domain};
fetch_provider_configuration(Domain0, Context) ->
    Domain = z_convert:to_binary(Domain0),
    DepKey = {openid_domain_config, Domain},
    case z_depcache:get(DepKey, Context) of
        undefined ->
            Domain1 = case binary:last(Domain) of
                $/ -> Domain;
                _ -> <<Domain/binary, $/>>
            end,
            Url = iolist_to_binary([ "https://", Domain1, ".well-known/openid-configuration" ]),
            case z_fetch:fetch_json(Url, [ {authorization, undefined} ], Context) of
                {ok, JSON} ->
                    case oidcc_provider_configuration:decode_configuration(JSON) of
                        {ok, Config} ->
                            z_depcache:set(DepKey, Config, 3600, [], Context),
                            {ok, Config};
                        {error, Reason} = Error ->
                            ?LOG_WARNING(#{
                                in => zotonic_mod_sso_openidc,
                                text => <<"Parse of fetched openid-configuration failed">>,
                                result => error,
                                reason => Reason,
                                domain => Domain,
                                url => Url
                            }),
                            Error
                    end;
                {error, {404, _Url, _Hs, _Sz, _Body}} ->
                    ?LOG_WARNING(#{
                        in => zotonic_mod_sso_openidc,
                        text => <<"Fetch of openid-configuration failed">>,
                        result => error,
                        reason => enoent,
                        domain => Domain,
                        url => Url
                    }),
                    {error, enoent};
                {error, Reason} = Error ->
                    ?LOG_WARNING(#{
                        in => zotonic_mod_sso_openidc,
                        text => <<"Fetch of openid-configuration failed">>,
                        result => error,
                        reason => Reason,
                        domain => Domain,
                        url => Url
                    }),
                    Error
            end;
        {ok, _} = Ok ->
            Ok
    end.


%% @doc Return the names used for the processes managing the OIDC worker and
%% worker configuration.
-spec local_provider_names(Name, Context) -> {WorkerName, CfgName} when
    Name :: atom(),
    Context :: z:context(),
    WorkerName :: atom(),
    CfgName :: atom().
local_provider_names(Name, Context) ->
    Site = z_context:site(Context),
    CfgName = binary_to_atom(
        iolist_to_binary([
            "oidc-config:",
            atom_to_binary(Name, utf8),
            $$,
            atom_to_binary(Site, utf8)
        ])),
    WorkerName = binary_to_atom(
        iolist_to_binary([
            "oidc-worker:",
            atom_to_binary(Name, utf8),
            $$,
            atom_to_binary(Site, utf8)
        ])),
    {WorkerName, CfgName}.


-spec scopes(Provider) -> Scopes when
    Provider :: provider(),
    Scopes :: [ Scope ],
    Scope :: atom().
scopes(#{ request_scopes := Scopes }) when is_list(Scopes), Scopes =/= [] ->
    case lists:member(<<"openid">>, Scopes) of
        true -> Scopes;
        false -> [ <<"openid">> | Scopes ]
    end;
scopes(_Provider) ->
    [ <<"openid">>, <<"email">> ].

-spec provider_name(Provider) -> ProviderName when
    Provider :: provider(),
    ProviderName :: provider_name().
provider_name(#{ name := Name }) ->
    Name.

-spec provider_credentials(Provider) -> Credentials | undefined when
    Provider :: provider(),
    Credentials :: {ClientId, ClientSecret},
    ClientId :: binary(),
    ClientSecret :: binary().
provider_credentials(#{ client_id := ClientId, client_secret := ClientSecret }) ->
    {ClientId, ClientSecret};
provider_credentials(_Provider) ->
    undefined.

-spec provider_has_userinfo(Provider) -> boolean() | undefined when
    Provider :: provider().
provider_has_userinfo(#{ is_retrieve_userinfo := HasUserInfo }) ->
    HasUserInfo;
provider_has_userinfo(_Provider) ->
    true.

-spec provider_email_required(Provider) -> boolean() | undefined when
    Provider :: provider().
provider_email_required(#{ is_email_required := IsEmailReq }) ->
    IsEmailReq;
provider_email_required(_Provider) ->
    true.

-spec provider_email_verified(Provider) -> boolean() | undefined when
    Provider :: provider().
provider_email_verified(#{ is_email_verified := IsEmailVerified }) ->
    IsEmailVerified;
provider_email_verified(_Provider) ->
    false.

-spec provider_add_username_pw(Provider) -> boolean() | undefined when
    Provider :: provider().
provider_add_username_pw(#{ is_add_username_pw := IsAddUsernamePw }) ->
    IsAddUsernamePw;
provider_add_username_pw(_Provider) ->
    true.

-spec provider_acr_values(Provider) -> AcrValues when
    Provider :: provider(),
    AcrValues :: [ acr_value() ].
provider_acr_values(#{ acr_values := AcrValues }) when is_list(AcrValues) ->
    AcrValues;
provider_acr_values(_Provider) ->
    [].

-spec provider_organizations(Provider) -> Organizations when
    Provider :: provider(),
    Organizations :: [ binary() ].
provider_organizations(#{ organizations := Organizations }) when is_list(Organizations) ->
    Organizations;
provider_organizations(_Provider) ->
    [].

-spec provider_is_mfa(Provider) -> boolean() when
    Provider :: provider().
provider_is_mfa(#{ acr_values := AcrValues }) when is_list(AcrValues) ->
    lists:any(fun is_mfa_acr/1, AcrValues);
provider_is_mfa(_) ->
    false.

% https://wiki.surfnet.nl/display/SsID/Using+Levels+of+Assurance+to+express+strength+of+authentication
% https://openid.net/specs/openid-connect-modrna-authentication-1_0.html#acr_values
%% @doc Check if an ACR value denotes that MFA must be used.
is_mfa_acr(<<"http://schemas.openid.net/policies/modrna/multi-factor">>) -> true;
is_mfa_acr(<<"mod-mf">>) -> true;
is_mfa_acr(<<"http://schemas.openid.net/policies/modrna/phishing-resistant">>) -> true;
is_mfa_acr(<<"mod-pr">>) -> true;
is_mfa_acr(ACR) ->
           re:run(ACR, <<"\\/loa2$">>) /= nomatch
    orelse re:run(ACR, <<"\\/loa3$">>) /= nomatch
    orelse re:run(ACR, <<"\\/sfo-level2$">>) /= nomatch
    orelse re:run(ACR, <<"\\/sfo-level3$">>) /= nomatch.

manage_schema(Version, Context) ->
    m_sso_openidc:install(Version, Context).

manage_data(_Version, _Context) ->
    % TODO: install default test server
    ok.
