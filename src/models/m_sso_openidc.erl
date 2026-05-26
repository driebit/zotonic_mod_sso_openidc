%% @author Driebit BV <tech@driebit.nl>
%% @copyright 2024-2026 Driebit BV
%% @doc Model for OpenID Connect providers.
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

-module(m_sso_openidc).

-export([
    m_get/3,

    is_authorized/1,
    is_user_external/2,

    find_by_name/2,

    list/1,
    list_auth_enabled/1,

    list_providers_all/1,
    list_providers_auth/1,
    list_providers_import/1,
    list_providers_for_domain/2,

    fetch/2,
    insert/3,
    update/3,
    delete/2,
    install/2,

    binary_array/1
]).

-include_lib("zotonic_core/include/zotonic.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

m_get([ <<"providers">>, <<"byid">>, Id ], _Msg, Context) ->
    case is_authorized(Context) of
        true ->
            case fetch(z_convert:to_integer(Id), Context) of
                {ok, App} -> {ok, {App, []}};
                {error, _} -> {error, error}
            end;
        false ->
            {error, eacces}
    end;
m_get([ <<"providers">>, <<"list">> ], _Msg, Context) ->
    case is_authorized(Context) of
        true ->
            case list(Context) of
                {ok, L} -> {ok, {L, []}};
                {error, _} -> {error, error}
            end;
        false ->
            {error, eacces}
    end;
m_get([ <<"providers">>, <<"list">>, <<"auth">> | Rest ], _Msg, Context) ->
    case list_providers_auth(Context) of
        {ok, Apps} ->
            {ok, {Apps, Rest}};
        {error, _} = Error ->
            Error
    end;
m_get([ <<"providers">>, <<"list">>, <<"import">> | Rest ], _Msg, Context) ->
    case list_providers_import(Context) of
        {ok, Apps} ->
            {ok, {Apps, Rest}};
        {error, _} = Error ->
            Error
    end;
m_get([ <<"providers">>, <<"list">>, <<"all">> | Rest ], _Msg, Context) ->
    case list_providers_all(Context) of
        {ok, Apps} ->
            {ok, {Apps, Rest}};
        {error, _} = Error ->
            Error
    end;
m_get([ <<"provider">>, Name, <<"is_config_loaded">> | Rest ], _Msg, Context) ->
    case is_authorized(Context) of
        true ->
            IsLoaded = case mod_sso_openidc:get_provider_configuration(Name, Context) of
                {ok, #oidcc_provider_configuration{}} ->
                    true;
                {error, _} ->
                    false
            end,
            {ok, {IsLoaded, Rest}};
        false ->
            {error, eacces}
    end;
m_get([ <<"provider">>, Name, <<"acr_values_supported">> | Rest ], _Msg, Context) ->
    case is_authorized(Context) of
        true ->
            case mod_sso_openidc:get_provider_configuration(Name, Context) of
                {ok, #oidcc_provider_configuration{ acr_values_supported = undefined }} ->
                    {ok, {[], Rest}};
                {ok, #oidcc_provider_configuration{ acr_values_supported = AcrValuesSupported }} ->
                    {ok, {AcrValuesSupported, Rest}};
                {error, _} = Error ->
                    Error
            end;
        false ->
            {error, eacces}
    end;
m_get([ <<"provider">>, Name, <<"scopes_supported">> | Rest ], _Msg, Context) ->
    case is_authorized(Context) of
        true ->
            case mod_sso_openidc:get_provider_configuration(Name, Context) of
                {ok, #oidcc_provider_configuration{ scopes_supported = undefined }} ->
                    {ok, {[], Rest}};
                {ok, #oidcc_provider_configuration{ scopes_supported = ScopesSupported }} ->
                    {ok, {ScopesSupported, Rest}};
                {error, _} = Error ->
                    Error
            end;
        false ->
            {error, eacces}
    end;
m_get([ <<"is_user_external">> | Rest ], _Msg, Context) ->
    {ok, {is_user_external(z_acl:user(Context), Context), Rest}}.


-spec is_user_external(UserId, Context) -> boolean() when
    UserId :: m_rsc:resource_id() | undefined,
    Context :: z:context().
is_user_external(undefined, _Context) ->
    false;
is_user_external(Id, Context) ->
    case m_rsc:p_no_acl(Id, <<"email_raw">>, Context) of
        undefined -> false;
        <<>> -> false;
        Email ->
            Domain = z_string:to_lower(lists:last(binary:split(Email, <<"@">>, [global]))),
            ProvId = z_db:q1("
                select a.id
                from sso_openidc_provider a
                where a.is_use_auth = true
                  and a.is_enabled = true
                  and a.grant_type <> 'client_credentials'
                  and $1 = any(a.domains)
                limit 1
                ",
                [ Domain ],
                Context),
            is_integer(ProvId)
    end.


-spec list(Context) -> {ok, [ Provider ]} | {error, Reason} when
    Provider :: mod_sso_openidc:provider(),
    Context :: z:context(),
    Reason :: term().
list(Context) ->
    case z_db:qmap("
        select *
        from sso_openidc_provider
        order by priority, name, id asc
        ",
        [],
        [ {keys, atom} ],
        Context)
    of
        {ok, L} ->
            L1 = lists:map(fun map_name_to_atom/1, L),
            {ok, L1};
        {error, _} = Error ->
            Error
    end.

-spec list_auth_enabled(Context) -> {ok, [ Provider ]} | {error, Reason} when
    Provider :: mod_sso_openidc:provider(),
    Context :: z:context(),
    Reason :: term().
list_auth_enabled(Context) ->
    case z_db:qmap("
        select *
        from sso_openidc_provider
        where is_use_auth = true
          and is_enabled = true
        order by priority, description, name, id
        ",
        [],
        [ {keys, atom} ],
        Context)
    of
        {ok, L} ->
            L1 = lists:map(fun map_name_to_atom/1, L),
            {ok, L1};
        {error, _} = Error ->
            Error
    end.

%% @doc List all providers that can be used for authentication.
-spec list_providers_auth( z:context() ) -> {ok, list( map() )} | {error, term()}.
list_providers_auth(Context) ->
    z_db:qmap("
        select a.id, a.name, a.domain, a.description, a.is_use_import, a.is_use_auth, a.logo_url
        from sso_openidc_provider a
        where a.is_use_auth = true
          and a.is_enabled = true
          and a.grant_type <> 'client_credentials'
        order by a.priority, a.description, a.name, a.id",
        Context).


%% @doc List all providers that can be used for import.
-spec list_providers_import( z:context() ) -> {ok, list( map() )} | {error, term()}.
list_providers_import(Context) ->
    z_db:qmap("
        select a.id, a.name, a.domain, a.description, a.is_use_import, a.is_use_auth, a.logo_url
        from sso_openidc_provider a
        where a.is_use_import = true
          and a.is_enabled = true
          and a.grant_type <> 'client_credentials'
        order by a.priority, a.description, a.name, a.id",
        Context).


%% @doc List all providers that can be used for authentication or import.
-spec list_providers_all( z:context() ) -> {ok, list( map() )} | {error, term()}.
list_providers_all(Context) ->
    z_db:qmap("
        select a.id, a.name, a.domain, a.description, a.is_use_import, a.is_use_auth, a.grant_type, a.logo_url
        from sso_openidc_provider a
        where (   a.is_use_auth = true
               or a.is_use_import = true)
          and a.is_enabled = true
          and a.grant_type <> 'client_credentials'
        order by a.priority, a.description, a.name, a.id",
        Context).

%% @doc List all enabled providers that handle authentication for a domain.
-spec list_providers_for_domain(Domain, Context) -> {ok, Providers} | {error, term()} when
    Domain :: binary() | string() | undefined,
    Context :: z:context(),
    Providers :: list( map() ).
list_providers_for_domain(undefined, _Context) ->
    {ok, []};
list_providers_for_domain(Domain, Context) ->
    case z_string:trim(z_string:to_lower(z_convert:to_binary(Domain))) of
        <<>> ->
            {ok, []};
        Domain1 ->
            z_db:qmap("
                select a.id, a.name, a.domain, a.description, a.is_use_import, a.is_use_auth, a.grant_type, a.logo_url
                from sso_openidc_provider a
                where a.is_use_auth = true
                  and a.is_enabled = true
                  and a.grant_type <> 'client_credentials'
                  and $1 = any(a.domains)
                order by a.priority, a.description, a.name, a.id
                ",
                [ Domain1 ],
                Context)
    end.

is_authorized(Context) ->
    z_acl:is_admin(Context)
    orelse z_acl:is_allowed(use, mod_sso_openidc, Context).

-spec find_by_name(Name, Context) -> {ok, Provider} | {error, Reason} when
    Name :: binary() | atom(),
    Context :: z:context(),
    Provider :: mod_sso_openidc:provider(),
    Reason :: term().
find_by_name(undefined, _Context) ->
    {error, enoent};
find_by_name(<<>>, _Context) ->
    {error, enoent};
find_by_name(testprovider, Context) ->
    {ok, test_provider(Context)};
find_by_name(<<"testprovider">>, Context) ->
    {ok, test_provider(Context)};
find_by_name(Name, Context) ->
    maybe_map_name_to_atom(z_db:qmap_row("
        select *
        from sso_openidc_provider
        where name = $1
        ",
        [ z_convert:to_binary(Name) ],
        [ {keys, atom} ],
        Context)).

-spec fetch(Id, Context) -> {ok, Provider} | {error, Reason} when
    Id :: pos_integer(),
    Provider :: mod_sso_openidc:provider(),
    Context :: z:context(),
    Reason :: term().
fetch(Id, Context) ->
    maybe_map_name_to_atom(z_db:qmap_row("
        select *
        from sso_openidc_provider
        where id = $1
        ",
        [ Id ],
        [ {keys, atom} ],
        Context)).

-spec insert(Name, Domain, Context) -> {ok, Id} | {error, Reason} when
    Name :: binary(),
    Domain :: binary(),
    Id :: pos_integer(),
    Context :: z:context(),
    Reason :: term().
insert(Name, Domain, Context) ->
    case z_db:q1("select count(*) from sso_openidc_provider where name = $1", [ Name ], Context) of
        1 ->
            ?LOG_WARNING(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Could not insert new OIDC provider">>,
                result => error,
                reason => duplicate_name,
                name => Name,
                domain => Domain
            }),
            {error, duplicate_name};
        0 ->
            case mod_sso_openidc:fetch_provider_configuration(Domain, Context) of
                {ok, #oidcc_provider_configuration{ issuer = Issuer }} ->
                    Args = #{
                        <<"name">> => Name,
                        <<"domain">> => Domain,
                        <<"issuer_url">> => Issuer,
                        <<"is_enabled">> => false,
                        <<"is_use_auth">> => true,
                        <<"is_use_import">> => false,
                        <<"is_test_server">> => false,
                        <<"is_email_required">> => true,
                        <<"is_email_verified">> => false,
                        <<"is_add_username_pw">> => true,
                        <<"priority">> => 99,
                        <<"organizations">> => [],
                        <<"domains">> => [],
                        <<"request_scopes">> => [ <<"openid">>, <<"email">>, <<"email_verified">>, <<"profile">> ],
                        <<"grant_type">> => <<"authorization_code">>,
                        <<"acr_values">> => []
                    },
                    case z_db:insert(sso_openidc_provider, Args, Context) of
                        {ok, AppId} ->
                            ?LOG_INFO(#{
                                in => zotonic_mod_sso_openidc,
                                text => <<"Inserted new OIDC provider">>,
                                result => ok,
                                provider_id => AppId,
                                name => Name,
                                domain => Domain
                            }),
                            {ok, AppId};
                        {error, Reason} = Error ->
                            ?LOG_ERROR(#{
                                in => zotonic_mod_sso_openidc,
                                text => <<"Could not insert new OIDC provider">>,
                                result => error,
                                reason => Reason,
                                name => Name,
                                domain => Domain
                            }),
                            Error
                    end;
                {error, _} ->
                    ?LOG_WARNING(#{
                        in => zotonic_mod_sso_openidc,
                        text => <<"Could not insert new OIDC provider">>,
                        result => error,
                        reason => oidc_config,
                        name => Name,
                        domain => Domain
                    }),
                    {error, oidc_config}
            end;
        {error, _} = Error ->
            Error
    end.

-spec update(Id, Provider, Context) -> ok | {error, Reason} when
    Id :: pos_integer(),
    Provider :: mod_sso_openidc:provider(),
    Context :: z:context(),
    Reason :: term().
update(Id, Provider, Context) ->
    Args = to_record(Provider),
    Args1 = maps:without([ <<"user_id">> ], Args),
    Args2 = Args1#{
        <<"modified">> => calendar:universal_time()
    },
    case z_db:update(sso_openidc_provider, Id, Args2, Context) of
        {ok, 1} ->
            ?LOG_INFO(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Updated OIDC provider">>,
                result => ok,
                app_id => Id
            }),
            Name = z_db:q1("select name from sso_openidc_provider where id = $1", [ Id ], Context),
            _ = mod_sso_openidc:maybe_reload_provider(Name, Context),
            ok;
        {ok, 0} ->
            ?LOG_ERROR(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Could not update OIDC provider">>,
                result => error,
                reason => enoent,
                app_id => Id
            }),
            {error, enoent};
        {error, Reason} = Error ->
            ?LOG_ERROR(#{
                in => zotonic_mod_sso_openidc,
                text => <<"Could not update OIDC provider">>,
                result => error,
                reason => Reason,
                app_id => Id
            }),
            Error
    end.

-spec delete(Id, Context) -> ok | {error, Reason} when
    Id :: pos_integer(),
    Context :: z:context(),
    Reason :: term().
delete(Id, Context) ->
    case z_db:q1("select name from sso_openidc_provider where id = $1", [ Id ], Context) of
        undefined ->
            ok;
        Name ->
            mod_sso_openidc:stop_provider(Name, Context),
            case z_db:delete(sso_openidc_provider, Id, Context) of
                {ok, 1} -> ok;
                {ok, 0} -> {error, enoent};
                {error, _} = Error -> Error
            end
    end.


%% @doc Ensure the name is an atom, as that is needed for the OIDC supervisor.
maybe_map_name_to_atom({ok, R}) -> {ok, map_name_to_atom(R)};
maybe_map_name_to_atom({error, _} = Error) -> Error.

map_name_to_atom(#{ name := Name } = App) ->
    App#{ name => binary_to_atom(Name, utf8) }.

to_record(OIDC) ->
    #{
        <<"is_enabled">> => z_convert:to_bool(maps:get(is_enabled, OIDC, true)),
        <<"is_use_auth">> => z_convert:to_bool(maps:get(is_use_auth, OIDC, true)),
        <<"is_use_import">> => z_convert:to_bool(maps:get(is_use_import, OIDC, true)),
        <<"is_test_server">> => z_convert:to_bool(maps:get(is_test_server, OIDC, false)),
        <<"is_email_required">> => z_convert:to_bool(maps:get(is_email_required, OIDC, false)),
        <<"is_email_verified">> => z_convert:to_bool(maps:get(is_email_verified, OIDC, false)),
        <<"is_add_username_pw">> => z_convert:to_bool(maps:get(is_add_username_pw, OIDC, false)),
        <<"has_userinfo">> => z_convert:to_bool(maps:get(has_userinfo, OIDC, false)),
        <<"priority">> => z_convert:to_integer(maps:get(priority, OIDC, 1)),
        <<"description">> => z_string:trim(z_convert:to_binary(maps:get(description, OIDC, <<>>))),
        <<"logo_url">> => z_html:sanitize_uri(z_string:trim(z_convert:to_binary(maps:get(logo_url, OIDC, <<>>)))),
        <<"client_id">> => z_string:trim(z_convert:to_binary(maps:get(client_id, OIDC, <<>>))),
        <<"client_secret">> => z_string:trim(z_convert:to_binary(maps:get(client_secret, OIDC, <<>>))),
        <<"grant_type">> => z_string:trim(z_convert:to_binary(maps:get(grant_type, OIDC, <<>>))),
        <<"organizations">> => lower_array(binary_array(maps:get(organizations, OIDC, []))),
        <<"domains">> => lower_array(binary_array(maps:get(domains, OIDC, []))),
        <<"request_scopes">> => lower_array(binary_array(maps:get(request_scopes, OIDC, []))),
        <<"acr_values">> => binary_array(maps:get(acr_values, OIDC, [])),
        <<"user_id">> => z_convert:to_integer(maps:get(user_id, OIDC, undefined)),
        <<"category_id">> => z_convert:to_integer(maps:get(category_id, OIDC, undefined))
    }.

trim_array(L) ->
    L1 = lists:map(fun z_string:trim/1, L),
    lists:filter(fun(V) -> V =/= <<>> end, L1).

lower_array(L) ->
    trim_array(lists:map(fun z_string:to_lower/1, L)).

-spec binary_array(Input) -> List when
    Input :: binary() | list() | undefined,
    List :: [ binary() ].
binary_array(undefined) ->
    [];
binary_array(B) when is_binary(B) ->
    binary:split(B, [<<" ">>, <<"\n">>, <<"\r">>, <<"\t">> ], [global, trim_all]);
binary_array(L) when is_list(L) ->
    trim_array(lists:map(fun z_convert:to_binary/1, L)).

% TODO: Review provider maps usage - maybe better to not pass this everywhere
% because of secrets that could accidentally get logged. Better pass the name
% only (with Context) and do the lookup within the innermost functions.
-spec test_provider(Context) -> mod_sso_oidc:provider() when
    Context :: z:context().
test_provider(Context) ->
    #{
        is_use_auth => true,
        is_use_import => true,
        is_test_server => true,
        is_email_required => true,
        is_email_verified => false,
        has_userinfo => true,
        name => testprovider,
        description => <<"Test server">>,
        client_id => z_context:hostname(Context),
        client_secret => <<"...">>,
        issuer_url => <<"https://connect.test.surfconext.nl">>,
        organizations => [],
        domains => [],
        request_scopes => [],
        acr_values => [],
        user_id => 1,
        category_id => undefined
    }.

install(_Version, Context) ->
    case z_db:table_exists(sso_openidc_provider, Context) of
        true ->
            install_is_email_verified(Context),
            install_domains(Context),
            ok;
        false ->
            [] = z_db:q("
                create table sso_openidc_provider (
                    id serial not null,
                    is_enabled boolean not null default false,
                    is_use_import boolean not null default false,
                    is_use_auth boolean not null default false,
                    is_test_server boolean not null default false,
                    is_email_required boolean not null default true,
                    is_email_verified boolean not null default false,
                    is_add_username_pw boolean not null default true,
                    has_userinfo boolean not null default false,
                    priority int not null default 1,
                    name character varying(80) not null,
                    domain character varying(120) not null,
                    description character varying(200) not null default '',
                    logo_url character varying(200),
                    issuer_url character varying(200) not null,
                    client_id character varying(200) not null default '',
                    client_secret character varying(200) not null default '',
                    grant_type character varying(80) not null default 'authorization_code',
                    organizations character varying(80)[],
                    domains character varying(80)[],
                    request_scopes character varying(80)[],
                    acr_values character varying(200)[],
                    category_id int,
                    user_id int,
                    created timestamp with time zone not null default now(),
                    modified timestamp with time zone not null default now(),

                    PRIMARY KEY (id),
                    CONSTRAINT sso_openidc_provider_name_key UNIQUE (name),

                    CONSTRAINT fk_sso_openidc_provider_user_id FOREIGN KEY (user_id)
                        REFERENCES rsc (id)
                        ON UPDATE CASCADE ON DELETE SET NULL,
                    CONSTRAINT fk_sso_openidc_provider_category_id FOREIGN KEY (category_id)
                        REFERENCES rsc (id)
                        ON UPDATE CASCADE ON DELETE SET NULL
                )", Context),
            [] = z_db:q("CREATE INDEX fki_sso_openidc_provider_user_id ON sso_openidc_provider (user_id)", Context),
            [] = z_db:q("CREATE INDEX fki_sso_openidc_provider_category_id ON sso_openidc_provider (category_id)", Context),

            z_db:flush(Context)
    end.

install_is_email_verified(Context) ->
    case z_db:column_exists(sso_openidc_provider, is_email_verified, Context) of
        true ->
            ok;
        false ->
            [] = z_db:q("
                alter table sso_openidc_provider
                add column is_email_verified boolean not null default false",
                Context),
            z_db:flush(Context)
    end.

install_domains(Context) ->
    case z_db:column_exists(sso_openidc_provider, domains, Context) of
        true ->
            ok;
        false ->
            [] = z_db:q("
                alter table sso_openidc_provider
                add column domains character varying(80)[]",
                Context),
            z_db:flush(Context)
    end.
