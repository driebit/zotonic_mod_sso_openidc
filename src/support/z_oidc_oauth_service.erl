%% @author Driebit BV
%% @copyright 2024-2026 Driebit BV
%% @doc Support routines for using OIDC as an external identity provider.
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

-module(z_oidc_oauth_service).

-export([
    title/1,
    oauth_version/0,
    authorize_url/3,
    fetch_access_token/5,
    auth_validated/3
]).

-include_lib("zotonic_core/include/zotonic.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

%% @doc Return the service title for display in templates
-spec title( z:context() ) -> binary().
title(_Context) ->
    <<"OIDC">>.

%% @doc Return the major OAuth version being used
-spec oauth_version() -> oidc.
oauth_version() ->
    oidc.

%% @doc Return the authorization url for the OAuth permission dialog.
-spec authorize_url( RedirectUrl, StateId, Context ) -> {ok, map()} | {error, Reason} when
    RedirectUrl :: binary(),
    StateId :: binary(),
    Context :: z:context(),
    Reason :: term().
authorize_url(RedirectUrl, StateId, Context) ->
    Provider = mod_sso_openidc:provider_by_name(z_context:get_q(<<"provider">>, Context), Context),
    ProviderName = mod_sso_openidc:provider_name(Provider),
    case mod_sso_openidc:ensure_provider(ProviderName, Context) of
        {ok, _WorkerName} ->
            {ok, WorkerConfig} = mod_sso_openidc:get_provider_configuration(ProviderName, Context),
            AcrValues = mod_sso_openidc:provider_acr_values(Provider),
            case check_acr_values(ProviderName, AcrValues, WorkerConfig) of
                {ok, AcrValues1} ->
                    Scopes = mod_sso_openidc:scopes(Provider),
                    Scopes1 = maybe_add_scopes(Scopes, WorkerConfig),
                    BaseOptions = #{
                        redirect_uri => RedirectUrl,
                        state => StateId,
                        scopes => lists:usort(Scopes1)
                    },
                    Options = case AcrValues1 of
                        [] -> BaseOptions;
                        _ ->
                            BaseOptions#{
                                url_extension => [
                                    {<<"acr_values">>, unicode:characters_to_binary(lists:join(" ", AcrValues1))}
                                ]
                            }
                    end,
                    {ClientId, ClientSecret} = mod_sso_openidc:provider_credentials(Provider),
                    {LocalWorkerName, _} = mod_sso_openidc:local_provider_names(ProviderName, Context),
                    case oidcc:create_redirect_url(LocalWorkerName, ClientId, ClientSecret, Options) of
                        {ok, Url} ->
                            {ok, #{
                                url => unicode:characters_to_binary(Url),
                                data => #{
                                    p => ProviderName
                                }
                            }};
                        {error, Reason} = Error ->
                            ?LOG_ERROR(#{
                                in => zotonic_mod_sso_openidc,
                                text => <<"Could not fetch redirect url from OpenIDC provider">>,
                                result => error,
                                reason => Reason,
                                provider => ProviderName,
                                worker => LocalWorkerName
                            }),
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} = Error ->
            ?LOG_ERROR(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Could not start OpenIDC provider">>,
                result => error,
                reason => Reason,
                provider => ProviderName
            }),
            Error
    end.

maybe_add_scopes(Scopes, #oidcc_provider_configuration{ scopes_supported = ScopesSupported }) ->
    case lists:member(<<"email_verified">>, ScopesSupported) of
        true ->
            case lists:member(<<"email">>, Scopes) of
                true -> [ <<"email_verified">> | Scopes ];
                false -> Scopes
            end;
        false ->
            Scopes
    end.

check_acr_values(_ProviderName, [], #oidcc_provider_configuration{ acr_values_supported = undefined }) ->
    {ok, []};
check_acr_values(ProviderName, AcrValues, #oidcc_provider_configuration{ acr_values_supported = undefined }) ->
    ?LOG_ERROR(#{
        in => zotonic_mod_sso_openidc,
        text => <<"OIDC requested unsupported ACR values">>,
        result => error,
        reason => acr_mismatch,
        requested => AcrValues,
        supported => [],
        unsupported => AcrValues,
        provider => ProviderName
    }),
    {error, acr_unsupported};
check_acr_values(ProviderName, AcrValues, #oidcc_provider_configuration{ acr_values_supported = Supported }) ->
    case AcrValues -- Supported of
        [] ->
            {ok, AcrValues};
        Unsupported ->
            ?LOG_ERROR(#{
                in => zotonic_mod_sso_openidc,
                text => <<"OIDC requested unsupported ACR values">>,
                result => error,
                reason => acr_mismatch,
                requested => AcrValues,
                supported => Supported,
                unsupported => Unsupported,
                provider => ProviderName
            }),
            {error, acr_unsupported}
    end.


%% @doc Exchange the code for an access token. The AuthData is as passed by authorize_url/3.
-spec fetch_access_token(Code, AuthData, Args, QArgs, Context) -> {ok, AccessData} | {error, Reason} when
    Code :: binary(),
    AuthData :: #{ p := binary(), force2fa := boolean() },
    Args :: list(),
    QArgs :: map(),
    Context :: z:context(),
    AccessData :: map(),
    Reason :: term().
fetch_access_token(Code, AuthData, _Args, _QArgs, Context) ->
    #{
        p := ProviderName
    } = AuthData,
    {ok, Provider} = m_sso_openidc:find_by_name(ProviderName, Context),
    {ClientId, ClientSecret} = mod_sso_openidc:provider_credentials(Provider),
    Url = mod_sso_openidc:return_url(Context),
    Opts = #{
        redirect_uri => Url,
        scope => mod_sso_openidc:scopes(Provider),
        preferred_auth_methods => [client_secret_basic]
    },
    {LocalWorkerName, _} = mod_sso_openidc:local_provider_names(ProviderName, Context),
    case oidcc:retrieve_token(Code, LocalWorkerName, ClientId, ClientSecret, Opts) of
        {ok, #oidcc_token{} = Token} ->
            AccessData = #{
                <<"access_token">> => Token,
                <<"provider">> => ProviderName
            },
            {ok, AccessData};
        {error, {http_error, StatusCode, HttpBodyResult}} ->
            ?LOG_ERROR(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Error fetching OIDC access token">>,
                result => error,
                reason => http_error,
                http_status => StatusCode,
                code => Code,
                body => HttpBodyResult,
                provider => ProviderName,
                options => Opts
            }),
            {error, http_error};
        {error, Reason} = Error ->
            ?LOG_ERROR(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Error fetching OIDC access token">>,
                result => error,
                reason => Reason,
                code => Code,
                provider => ProviderName,
                options => Opts
            }),
            Error
    end.


%% @doc Fetch the validated user data from the id_token
auth_validated(#{
        <<"access_token">> := #oidcc_token{
            id = #oidcc_token_id{
                claims = #{ <<"sub">> := Subject } = Claims
            }
        } = Token,
        <<"provider">> := ProviderName
    }, Args, Context) when is_atom(ProviderName) ->
    % io:format("~n~p~n", [ Token ]),
    Provider = mod_sso_openidc:provider_by_name(ProviderName, Context),
    IsEmailRequired = mod_sso_openidc:provider_email_required(Provider),
    IsEmailVerified = mod_sso_openidc:provider_email_verified(Provider),
    UserInfo = case mod_sso_openidc:provider_has_userinfo(Provider) of
        true ->
            {LocalWorkerName, _} = mod_sso_openidc:local_provider_names(ProviderName, Context),
            {ClientId, ClientSecret} = mod_sso_openidc:provider_credentials(Provider),
            case oidcc:retrieve_userinfo(Token, LocalWorkerName, ClientId, ClientSecret, #{}) of
                {ok, UInf} ->
                    UInf;
                {error, Reason} ->
                    ?LOG_ERROR(#{
                        text => <<"[oidc] error fetching user info">>,
                        in => zotonic_mod_sso_openidc,
                        result => error,
                        reason => Reason,
                        provider => ProviderName,
                        subject => Subject
                    }),
                    #{}
            end;
        false ->
            #{}
    end,
    {Email, IsVerified} = extract_email(Claims, UserInfo, IsEmailVerified),
    FullName = maps:get(<<"name">>, Claims, maps:get(<<"name">>, UserInfo, undefined)),
    FirstName = maps:get(<<"given_name">>, Claims, maps:get(<<"given_name">>, UserInfo, undefined)),
    LastName = maps:get(<<"family_name">>, Claims, maps:get(<<"family_name">>, UserInfo, undefined)),
    Category = case Provider of
        #{ category_id := undefined } -> person;
        #{ category_id := CatId } -> CatId
    end,
    PersonProps = #{
        <<"category_id">> => Category,
        <<"is_published">> => true,
        <<"title">> => FullName,
        <<"name_first">> => FirstName,
        <<"name_surname">> => LastName,
        <<"email">> => Email
    },
    Identities = if
        Email =:= undefined -> [];
        true -> [ #{ type => <<"email">>, key => Email, is_verified => IsVerified } ]
    end,
    ServiceProviderName = z_convert:to_binary(maps:get(name, Provider)),
    ServiceUidPrefixed = <<ServiceProviderName/binary, $:, Subject/binary>>,
    IsOrgOk = case mod_sso_openidc:provider_organizations(Provider) of
        [] ->
            true;
        Orgs ->
            case extract_org(Claims, UserInfo) of
                undefined when is_binary(Email), IsEmailVerified, IsVerified ->
                    % If the OpenIDC provider is administrated to only return verified
                    % email claims then we can take the domain of the email as the
                    % domain of the user and check it against the allowed orgs.
                    case binary:split(Email, <<"@">>, [ global, trim_all ]) of
                        [] -> false;
                        EmailParts ->
                            EmailDomain = lists:last(EmailParts),
                            lists:member(z_string:to_lower(EmailDomain), Orgs)
                    end;
                undefined ->
                    false;
                Org ->
                    lists:member(z_string:to_lower(Org), Orgs)
            end
    end,
    if
        IsEmailRequired andalso Email =:= undefined ->
            {error, email_required};
        not IsOrgOk ->
            {error, organization};
        true ->
            IsConnect = z_convert:to_bool(proplists:get_value(<<"is_connect">>, Args)),
            AddUsername = not IsConnect andalso mod_sso_openidc:provider_add_username_pw(Provider),
            ?LOG_INFO(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Authentication using OpenIDC SSO">>,
                result => ok,
                service => mod_sso_openidc,
                service_uid => ServiceUidPrefixed,
                email => Email,
                email_verified => IsVerified,
                identities => Identities,
                ensure_username_pw => AddUsername,
                is_connect => IsConnect,
                person_props => PersonProps
            }),
            {ok, #auth_validated{
                service = mod_sso_openidc,
                service_uid = ServiceUidPrefixed,
                service_props = [],
                props = PersonProps,
                identities = Identities,
                ensure_username_pw = AddUsername,
                is_connect = IsConnect
            }}
    end.

%% @doc Extract the email address from the claims or the profile. The 'email_verified' flag
%% defines if the email is verified. In the absence of the flag we have to assume that the
%% email has been verified.
extract_email(#{ <<"verified_primary_email">> := Email }, _Profile, _IsEmailVerified) when is_binary(Email), Email =/= <<>> ->
    % Optional claim in Azure
    {Email, true};
extract_email(#{ <<"email">> := Email }, _Profile, true) when is_binary(Email), Email =/= <<>> ->
    {Email, true};
extract_email(_Claims, #{ <<"email">> := Email }, true) when is_binary(Email), Email =/= <<>> ->
    {Email, true};
extract_email(#{ <<"email">> := Email, <<"email_verified">> := Verified }, _Profile, _IsEmailVerified) when is_binary(Email), Email =/= <<>> ->
    {Email, z_convert:to_bool(Verified)};
extract_email(#{ <<"email">> := Email }, _Profile, IsEmailVerified) when is_binary(Email), Email =/= <<>> ->
    {Email, IsEmailVerified};
extract_email(_Claims, #{<<"email">> := Email, <<"email_verified">> := Verified }, _IsEmailVerified) when is_binary(Email), Email =/= <<>> ->
    {Email, z_convert:to_bool(Verified)};
extract_email(_Claims, #{ <<"email">> := Email }, IsEmailVerified) when is_binary(Email), Email =/= <<>> ->
    {Email, IsEmailVerified};
extract_email(_Claims, _Profile, _IsEmailVerified) ->
    {undefined, false}.

%% @doc Extract the home organization, if it is undefined then take the domain name
%% of the verified email address from the Claims.
extract_org(#{ <<"schac_home_organization">> := Org }, _Profile) when is_binary(Org) ->
    Org;
extract_org(_Claims, #{ <<"schac_home_organization">> := Org }) when is_binary(Org) ->
    Org;
extract_org(_Claims, _Profile) ->
    undefined.

