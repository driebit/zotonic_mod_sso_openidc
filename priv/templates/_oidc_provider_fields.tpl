{% with m.sso_openidc.provider[app.name].is_config_loaded as is_loaded %}

{% if not is_loaded %}
    <div class="alert alert-danger">
        <b>{_ The configuration could not be loaded. _}</b>
        {_ Check the issuer URL and try again. _}
    </div>
{% endif %}

    <div class="form-group">
        <table class="table table-compact">
            <tr>
                <td>{_ Issuer domain _}</td><td><b>{{ app.domain|escape }}</b></td>
            </tr>
            <tr>
                <td>{_ Issuer URL _}</td><td><b>{{ app.issuer_url|escape }}</b></td>
            </tr>
         </table>
    </div>

    <div class="form-group">
        <label class="checkbox">
            <input type="checkbox" name="is_enabled" {% if app.is_enabled and is_loaded %}checked{% endif %}>
            {_ Enable this provider _}
        </label>
    </div>

    <div class="row">
        <div class="form-group col-sm-8">
            <div class="label-floating">
                <input id="{{ #description }}" type="text" value="{{ app.description|escape }}" class="form-control" name="description" required placeholder="{_ Description - shows up on button _}">
                <label class="control-label" for="description">{_ Description - shows up on button _}</label>
                {% validate id=#description name="description" type={presence} %}
            </div>
        </div>
        <div class="form-group col-sm-4">
            <label class="control-label">{_ Display order on login screen _}</label>
            <select class="form-control" name="priority" style="max-width: 10ch">
                <option></option>
                {% for n in 1|range:20 %}
                    <option value="{{ n }}" {% if app.priority == n %}selected{% endif %}>
                        {{ n }}
                    </option>
                {% endfor %}
            </select>
        </div>
    </div>

    <div class="form-group">
        <div class="label-floating">
            <input id="{{ #logo_url }}" type="text" value="{{ app.logo_url|escape }}" class="form-control" name="logo_url" placeholder="{_ Logo URL or path _}">
            <label class="control-label" for="logo_url">{_ Logo URL or path _}</label>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-6">
            <div class="form-group">
                <div class="label-floating">
                    <input id="{{ #client_id }}" type="text" value="{{ app.client_id|escape }}" class="form-control" name="client_id" required placeholder="{_ Client ID _}">
                    <label class="control-label" for="client_id">{_ Client ID _}</label>
                    {% validate id=#client_id name="client_id" type={presence} %}
                </div>
            </div>
        </div>
        <div class="col-sm-6">
            <div class="form-group">
                <div class="label-floating">
                    <input id="{{ #client_secret }}" type="text" value="{{ app.client_secret|escape }}" class="form-control" name="client_secret" required placeholder="{_ Client Secret _}">
                    <label class="control-label" for="client_secret">{_ Client Secret _}</label>
                    {% validate id=#client_secret name="client_secret" type={presence} %}
                </div>
            </div>
        </div>
    </div>

    <div class="form-group">
        <label class="control-label" for="grant_type">{_ Token grant method _}</label>
        <select class="form-control" name="grant_type" style="max-width: 30ch">
            <option value="authorization_code">
                Authorization Code ({_ default _})
            </option>
            <option value="client_credentials" {% if app.grant_type == 'client_credentials' %}selected{% endif %} disabled>
                Client Credentials
            </option>
        </select>
    </div>
    <p class="help-block">
        {% trans "The “{code}” method redirects the user to the remote website to obtain an access token. “{client}” allows an admin user to directly fetch a token from the remote website."
            code="Authorization Code"
            client="Client Credentials"
        %}
    </p>

    <div class="form-group">
        <label class="checkbox">
            <input type="checkbox" name="is_test_server" {% if app.is_test_server %}checked{% endif %}>
            {_ This is a test server, will only be available on development and test sites _}
        </label>
        <label class="checkbox">
            <input type="checkbox" name="is_use_auth" {% if app.is_use_auth %}checked{% endif %}>
            {% trans "Allow users on the remote website to authenticate here (using “{code}”)"
                    code="Authorization Code"
            %}
        </label>
        <label class="checkbox">
            <input type="checkbox" name="has_userinfo" {% if app.has_userinfo %}checked{% endif %}>
            {_ This server provides additional user information, like the user’s name and email address  _}
        </label>
        <label class="checkbox">
            <input type="checkbox" name="is_email_required" {% if app.is_email_required %}checked{% endif %}>
            {_ An email address must be provided to be able to log in  _}
        </label>
        <label class="checkbox">
            <input type="checkbox" name="is_email_verified" {% if app.is_email_verified %}checked{% endif %}>
            {_ Trust that all email addresses are verified by the server’s administrator. _}
        </label>
        <label class="checkbox">
            <input type="checkbox" name="is_add_username_pw" {% if app.is_add_username_pw %}checked{% endif %}>
            {_ Add a username/password on signup. A new user will be able to logon with a username/password.  _}
        </label>

{% comment %}
        <label class="checkbox">
            <input type="checkbox" name="is_use_import" {% if app.is_use_import %}checked{% endif %}> {_ Allow import of content from the remote website _}
        </label>
        <label class="checkbox">
            <input type="checkbox" value="1" name="is_extend_automatic" {% if app.is_extend_automatic %}checked{% endif %}>
            {% trans "Automatically extend tokens obtained using “{client}” before they expire"
                    client="Client Credentials"
            %}
        </label>
{% endcomment %}
    </div>

    <div class="form-group">
        <details>
            <summary>{_ Scopes requested _}</summary>
            <p class="help-block">{_ Information we request access to. Defaults to <tt>openid email</tt>. _}</p>
            {% if is_loaded %}
                <ul class="list-unstyled list-inline">
                    {% for scope in m.sso_openidc.provider[app.name].scopes_supported %}
                        <li>
                            <label class="checkbox">
                                <input type="checkbox" name="request_scopes[]" value="{{ scope|escape }}"
                                    {% if scope == 'openid' or scope|member:app.request_scopes %}
                                        checked
                                    {% endif %}>
                                {{ scope|escape }}
                            </label>
                        </li>
                    {% empty %}
                        <li>{_ No supported scopes found. _}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <p class="text-danger">{_ Could not load the OpenID configuration at the domain. _}</p>
            {% endif %}
        </details>
    </div>

    <div class="form-group">
        <details>
            <summary>{_ Elevated ACR values _}</summary>
            <p class="help-block">{_ Elevated Authentication Context Class References for using this provider. _}</p>
            {% if is_loaded %}
                <ul class="list-unstyled">
                    {% for acr in m.sso_openidc.provider[app.name].acr_values_supported %}
                        <li>
                            <label class="checkbox">
                                <input type="checkbox" name="acr_values[]" value="{{ acr|escape }}"
                                    {% if acr|member:app.acr_values %}
                                        checked
                                    {% endif %}>
                                {{ acr|escape }}
                            </label>
                        </li>
                    {% empty %}
                        <li>{_ No supported ACR values found. _}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <p class="text-danger">{_ Could not load the OpenID configuration at the domain. _}</p>
            {% endif %}
        </details>
    </div>

    <div class="form-group">
        <div class="label-floating">
            <textarea id="{{ #orgs }}" type="text" value="" class="form-control" name="organizations" placeholder="{_ Organizations _}">{% for d in app.organizations %}{{ d|escape }} {% endfor %}</textarea>
            <label class="control-label" for="{{ #orgs }}">{_ Organizations _}</label>
            <p class="help-block">{_ Organizations acceptable for authentication using this OpenID provider. One of these must match the returned <tt>shacHomeOrganization</tt>. Separate multiple organizations with a comma, newline or spaces. _} {_ If the server does not return the organization and the returned email address is verified, then the email domain is used as organization. _}</p>
        </div>
    </div>

    <div class="form-group">
        <div class="label-floating">
            <textarea id="{{ #domains }}" type="text" value="" class="form-control" name="domains" placeholder="{_ Domains _}">{% for d in app.domains %}{{ d|escape }} {% endfor %}</textarea>
            <label class="control-label" for="{{ #domains }}">{_ Domains _}</label>
            <p class="help-block">{_ The email domains this provider should handle. Users with one of these domains as their primary email address will be redirected to this provider. Separate multiple domains with a comma, newline or spaces. _}</p>
        </div>
    </div>

    <div class="form-group">
        <label class="control-label">{_ Signup category _}</label>
        <select name="category_id" class="form-control">
            <option value=""></option>
            {% for c in m.category.tree_flat %}
                <option value="{{c.id}}" {% if c.id == app.category_id %}selected{% endif %}>
                    {{ c.indent }}{{ c.id.title|default:c.id.name }}
                </option>
            {% endfor %}
        </select>
        <p class="help-block">{_ If the OIDC login is a new signup then this will be the category of the newly created user resource. Defaults to <tt>person</tt>. _}</p>
    </div>

{% endwith %}

