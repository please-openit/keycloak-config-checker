package it.pleaseopen.configchecker.realmresource;

import java.util.stream.Stream;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.admin.AdminAuth;

public class RealmConfigChecker extends AdminAuth implements RealmResourceProvider {
    private KeycloakContext context;
    private KeycloakSession session;

    protected RealmModel realm;

    @Context
    UriInfo uriInfo;

    public RealmConfigChecker(KeycloakSession session) {
        super(session.getContext().getRealm(),
                Tokens.getAccessToken(session),
                new AppAuthManager.BearerTokenAuthenticator(session).authenticate().getUser(),
                session.getContext().getClient());
        context = session.getContext();
        this.realm = context.getRealm();
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    @GET
    @NoCache
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/realm/check/details")
    public Response checkRealmConfigDetails() {
        ClientModel clientModel = session.clients().getClientByClientId(realm, "configchecker");

        if(!hasAppRole(clientModel, "details")){
            return Response.status(Response.Status.FORBIDDEN.getStatusCode(), "not allowed").build();
        }

        return checkRealmConfig(true);
    }

    @GET
    @NoCache
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/realm/check")
    public Response checkRealmConfigMetric() {
        ClientModel clientModel = session.clients().getClientByClientId(realm, "configchecker");

        if(!hasAppRole(clientModel, "metrics")){
            return Response.status(Response.Status.FORBIDDEN.getStatusCode(), "not allowed").build();
        }

        return checkRealmConfig(false);
    }

    public Response checkRealmConfig(Boolean details) {
        if (details == null) {
            details = false;
        }

        StringBuilder output = new StringBuilder();
        StringBuilder outputProm = new StringBuilder();
        // check if bruteforce is enabled or not

        if (!this.realm.isBruteForceProtected()) {
            output.append("BRUTE FORCE IS DISABLED \n");
            outputProm.append("brute_force_disabled 1\n");
        } else {
            outputProm.append("brute_force_disabled 0\n");
        }

        // CHECK RESET PASSWORD && VERIFY EMAIL && LOGIN WITH EMAIL
        if (this.realm.isVerifyEmail() == false && this.realm.isLoginWithEmailAllowed() == true
                && this.realm.isResetPasswordAllowed() == true) {
            output.append("CHECK RESET PASSWORD && VERIFY EMAIL && LOGIN WITH EMAIL \n");
            outputProm.append("reset_password_and_verify_email_and_login_with_email 1\n");
        } else {
            outputProm.append("reset_password_and_verify_email_and_login_with_email 0\n");
        }

        // CHECK RESET PASSWORD && EMAIL SERVER
        if (this.realm.isResetPasswordAllowed() == true && this.realm.getSmtpConfig().get("smtpServer.host") == null) {
            output.append("CHECK RESET PASSWORD && EMAIL SERVER \n");
            outputProm.append("reset_password_and_email_server 1\n");
        } else {
            outputProm.append("reset_password_and_email_server 0\n");
        }

        // CHECK REALM WITH ACCESS TOKEN > 5mn
        if (this.realm.getAccessCodeLifespan() > 300) {
            output.append("ACCESS TOKEN LIFESPAN IS TOO LONG (> 5min) " + this.realm.getAccessCodeLifespan() + " \n");
            outputProm.append("access_token_lifespan_is_too_long 1\n");
        } else {
            outputProm.append("access_token_lifespan_is_too_long 0\n");
        }

        // CHECK EVENTS
        if (this.realm.isEventsEnabled() || this.realm.isAdminEventsDetailsEnabled()) {
            output.append("EVENTS ARE SAVED \n");
            outputProm.append("events_are_saved 1\n");
        } else {
            outputProm.append("events_are_saved 0\n");
        }

        // CHECK offline_access is default
        RoleModel offlineAccess = realm.getRole("offline_access");
        if (this.realm.getDefaultRole().hasRole(offlineAccess)) {
            output.append("DEFAULT ROLE OFFLINE_ACCESS");
            outputProm.append("default_role_offline_access 1\n");
        } else {
            outputProm.append("default_role_offline_access 0\n");
        }

        if (details)
            return Response.ok(output.toString(), MediaType.TEXT_PLAIN).build();
        else
            return Response.ok(outputProm.toString(), MediaType.TEXT_PLAIN).build();
    }

    @GET
    @NoCache
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/clients/check/details")
    public Response checkClientsConfigDetails() {
        ClientModel clientModel = session.clients().getClientByClientId(realm, "configchecker");

        if(!hasAppRole(clientModel, "details")){
            return Response.status(Response.Status.FORBIDDEN.getStatusCode(), "not allowed").build();
        }

        return checkClientsConfig(true);
    }

    @GET
    @NoCache
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/clients/check")
    public Response checkClientsConfigMetric() {
        ClientModel clientModel = session.clients().getClientByClientId(realm, "configchecker");

        if(!hasAppRole(clientModel, "metrics")){
            return Response.status(Response.Status.FORBIDDEN.getStatusCode(), "not allowed").build();
        }

        return checkClientsConfig(false);
    }

    public Response checkClientsConfig(Boolean details) {
        if (details == null) {
            details = false;
        }
        StringBuilder output = new StringBuilder();
        StringBuilder outputProm = new StringBuilder();
        // CHECK CLIENTS WITH REFRESH TOKEN ON CLIENT CREDENTIALS
        Stream<ClientModel> streamClientsWithRefreshOnClientCredentials = realm.getClientsStream()
                .filter((ClientModel client) -> {
                    if (client.getAttribute("client_credentials.use_refresh_token") != null)
                        return Boolean.getBoolean(client.getAttribute("client_credentials.use_refresh_token"))
                                & client.isServiceAccountsEnabled();
                    return false;
                });
        if (details) {
            streamClientsWithRefreshOnClientCredentials.forEach(e -> {
                output.append("CLIENTS WITH REFRESH TOKEN ON CLIENT CREDENTIALS : " + e.getClientId() + "\n");
            });
        } else {
            outputProm.append("clients_with_refresh_token_on_client_credentials "
                    + streamClientsWithRefreshOnClientCredentials.count() + "\n");
        }

        // CHECK CLIENTS WITH IMPLICIT FLOW
        Stream<ClientModel> streamClientsWithImplicit = realm.getClientsStream().filter((ClientModel client) -> {
            return client.isImplicitFlowEnabled();
        });

        if (details) {
            streamClientsWithImplicit.forEach(e -> {
                output.append("IMPLICIT FLOW ENABLED : " + e.getClientId() + "\n");

            });
        } else {
            outputProm.append("implicit_flow_enabled " + streamClientsWithImplicit.count() + "\n");
        }

        // CHECK CLIENTS WITH DIRECT ACCESS GRANT
        Stream<ClientModel> streamClientsWithDirectGrant = realm.getClientsStream().filter((ClientModel client) -> {
            return client.isDirectAccessGrantsEnabled();
        });
        if (details) {
            streamClientsWithDirectGrant.forEach(e -> {
                output.append("DIRECT ACCESS GRANT ENABLED : " + e.getClientId() + "\n");

            });

        } else {
            outputProm.append("direct_access_grant_enabled " + streamClientsWithDirectGrant.count() + "\n");
        }

        // CHECK CLIENTS WITH BAD REDIRECT URIS
        Stream<ClientModel> streamBadRedirect = realm.getClientsStream().filter((ClientModel client) -> {
            return String.join("", client.getRedirectUris()).contains("*");
        });

        if (details) {
            streamBadRedirect.forEach(e -> {
                output.append("BAD REDIRECT URIS : " + e.getClientId() + "\n");
            });
        } else {
            outputProm.append("bad_redirect_uri " + streamBadRedirect.count() + "\n");
        }

        // CHECK CLIENTS SCOPES : OFFLINE
        Stream<ClientModel> streamClientsWithScopeOffline = realm.getClientsStream().filter((ClientModel client) -> {
            return client.getClientScopes(false).keySet().contains("offline_access");
        });
        if (details) {
            streamClientsWithScopeOffline.forEach(e -> {
                output.append("SCOPE OFFLINE : " + e.getClientId() + "\n");

            });
        } else {
            outputProm.append("scope_offline " + streamClientsWithScopeOffline.count() + "\n");
        }

        // CHECK CLIENTS WITH FULL SCOPES ALLOWED AND ROLES SCOPE
        Stream<ClientModel> streamClientsWithFullScopesAndRoles = realm.getClientsStream()
                .filter((ClientModel client) -> {
                    return (client.getClientScopes(false).keySet().contains("roles") & client.isFullScopeAllowed());
                });

        if (details) {
            streamClientsWithFullScopesAndRoles.forEach(e -> {
                output.append("FULL SCOPE ALLOWED AND SCOPE ROLES : " + e.getClientId() + "\n");

            });
        } else {
            outputProm
                    .append("full_scope_allowed_and_scope_roles " + streamClientsWithFullScopesAndRoles.count() + "\n");
        }

        // CHECK CLIENTS WITH ACCES TOKEN > 5mn
        Stream<ClientModel> streamClientsWithLongAccessToken = realm.getClientsStream().filter((ClientModel client) -> {
            if (client.getAttribute("access.token.lifespan") != null)
                return Integer.parseInt(client.getAttribute("access.token.lifespan")) > 300;
            return false;
        });
        if (details) {
            streamClientsWithLongAccessToken.forEach(e -> {
                output.append("ACCESS TOKEN LIFESPAN IS TOO LONG (>5min) : " + e.getClientId() + "\n");

            });
        } else {
            outputProm.append("access_token_lifespan_too_long " + streamClientsWithLongAccessToken.count() + "\n");
        }

        // CHECK DEFAULT CLIENT SCOPES, roles and offline_access as default
        Stream<ClientModel> streamClientsWithRoles = realm.getClientsStream().filter((ClientModel client) -> {
            return (client.getClientScopes(true).keySet().contains("roles"));
        });
        if (details) {
            streamClientsWithRoles.forEach(e -> {
                output.append("ROLES SCOPE AS DEFAULT : " + e.getClientId() + "\n");

            });
        } else {
            outputProm.append("roles_scope_as_default " + streamClientsWithRoles.count() + "\n");
        }

        Stream<ClientModel> streamClientsWithOffline = realm.getClientsStream().filter((ClientModel client) -> {
            return (client.getClientScopes(true).keySet().contains("offline_access"));
        });
        if (details) {
            streamClientsWithOffline.forEach(e -> {
                output.append("OFFLINE SCOPE AS DEFAULT : " + e.getClientId() + "\n");

            });
        } else {
            outputProm.append("offline_scope_as_default " + streamClientsWithOffline.count() + "\n");
        }

        if (details)
            return Response.ok(output.toString(), MediaType.TEXT_PLAIN).build();
        else
            return Response.ok(outputProm.toString(), MediaType.TEXT_PLAIN).build();
    }

    @GET
    @NoCache
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/users/check/details")
    public Response checkUsersConfigDetails() {
        ClientModel clientModel = session.clients().getClientByClientId(realm, "configchecker");

        if(!hasAppRole(clientModel, "details")){
            return Response.status(Response.Status.FORBIDDEN.getStatusCode(), "not allowed").build();
        }

        return checkUsersConfig(true);
    }

    @GET
    @NoCache
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/users/check")
    public Response checkUsersConfigMetric() {
        ClientModel clientModel = session.clients().getClientByClientId(realm, "configchecker");

        if(!hasAppRole(clientModel, "metrics")){
            return Response.status(Response.Status.FORBIDDEN.getStatusCode(), "not allowed").build();
        }

        return checkUsersConfig(false);
    }

    public Response checkUsersConfig(Boolean details) {
        if (details == null) {
            details = false;
        }
        StringBuilder output = new StringBuilder();
        StringBuilder outputProm = new StringBuilder();

        RoleModel offlineAccess = realm.getRole("offline_access");

        Stream<UserModel> streamUsersOfflineAccess = session.users().getRoleMembersStream(realm, offlineAccess, 0, 10);
        if (details) {
            streamUsersOfflineAccess.forEach(e -> {
                output.append("USER WITH offline_access : " + e.getUsername() + "\n");
            });
        } else {
            outputProm.append("users_with_offline_access " + streamUsersOfflineAccess.count() + "\n");
        }

        if (realm.getName().equals("master")) {
            RoleModel realmAdmin = realm.getRole("admin");
            Stream<UserModel> streamUsersAdmin = session.users().getRoleMembersStream(realm, realmAdmin, 0, 10);
            if (details) {
                streamUsersAdmin.forEach(e -> {
                    output.append("USER WITH admin ROLE ON MASTER : " + e.getUsername() + "\n");
                });
            } else {
                outputProm.append("users_with_admin_role_on_master " + streamUsersAdmin.count() + "\n");
            }

        } else {
            RoleModel realmManagementRole = realm.getRole("realm-management");
            Stream<UserModel> streamUsersRealmManagement = session.users().getRoleMembersStream(realm,
                    realmManagementRole, 0, 10);
            if (details) {
                streamUsersRealmManagement.forEach(e -> {
                    output.append("USER WITH realm_management ROLE : " + e.getUsername() + "\n");
                });
            } else {
                outputProm.append("users_with_realm_management " + streamUsersRealmManagement.count() + "\n");
            }
        }

        if (details)
            return Response.ok(output.toString(), MediaType.TEXT_PLAIN).build();
        else
            return Response.ok(outputProm.toString(), MediaType.TEXT_PLAIN).build();

    }
}
