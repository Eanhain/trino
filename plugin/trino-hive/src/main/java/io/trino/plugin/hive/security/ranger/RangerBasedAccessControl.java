/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.hive.security.ranger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Inject;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.Request;
import io.airlift.json.JsonCodec;
import io.trino.spi.TrinoException;
import io.trino.spi.catalog.CatalogName;
import io.trino.spi.connector.ConnectorAccessControl;
import io.trino.spi.connector.ConnectorSecurityContext;
import io.trino.spi.connector.SchemaRoutineName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.function.SchemaFunctionName;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.Privilege;
import io.trino.spi.security.TrinoPrincipal;
import io.trino.spi.security.ViewExpression;
import io.trino.spi.type.Type;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.apache.ranger.plugin.util.ServicePolicies;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.http.client.HttpUriBuilder.uriBuilderFrom;
import static io.airlift.http.client.JsonResponseHandler.createJsonResponseHandler;
import static io.airlift.http.client.Request.Builder.prepareGet;
import static io.airlift.http.client.StringResponseHandler.createStringResponseHandler;
import static io.airlift.json.JsonCodec.jsonCodec;
import static io.airlift.json.JsonCodec.listJsonCodec;
import static io.trino.plugin.hive.HiveErrorCode.HIVE_RANGER_SERVER_ERROR;
import static io.trino.plugin.hive.security.ranger.RangerBasedAccessControlConfig.RANGER_REST_POLICY_MGR_DOWNLOAD_URL;
import static io.trino.plugin.hive.security.ranger.RangerBasedAccessControlConfig.RANGER_REST_USER_GROUP_URL;
import static io.trino.plugin.hive.security.ranger.RangerBasedAccessControlConfig.RANGER_REST_USER_ROLES_URL;
import static io.trino.spi.security.AccessDeniedException.denyAddColumn;
import static io.trino.spi.security.AccessDeniedException.denyAlterColumn;
import static io.trino.spi.security.AccessDeniedException.denyCommentColumn;
import static io.trino.spi.security.AccessDeniedException.denyCommentTable;
import static io.trino.spi.security.AccessDeniedException.denyCommentView;
import static io.trino.spi.security.AccessDeniedException.denyCreateFunction;
import static io.trino.spi.security.AccessDeniedException.denyCreateMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyCreateRole;
import static io.trino.spi.security.AccessDeniedException.denyCreateSchema;
import static io.trino.spi.security.AccessDeniedException.denyCreateTable;
import static io.trino.spi.security.AccessDeniedException.denyCreateView;
import static io.trino.spi.security.AccessDeniedException.denyCreateViewWithSelect;
import static io.trino.spi.security.AccessDeniedException.denyDeleteTable;
import static io.trino.spi.security.AccessDeniedException.denyDenySchemaPrivilege;
import static io.trino.spi.security.AccessDeniedException.denyDenyTablePrivilege;
import static io.trino.spi.security.AccessDeniedException.denyDropColumn;
import static io.trino.spi.security.AccessDeniedException.denyDropFunction;
import static io.trino.spi.security.AccessDeniedException.denyDropMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyDropRole;
import static io.trino.spi.security.AccessDeniedException.denyDropSchema;
import static io.trino.spi.security.AccessDeniedException.denyDropTable;
import static io.trino.spi.security.AccessDeniedException.denyDropView;
import static io.trino.spi.security.AccessDeniedException.denyExecuteProcedure;
import static io.trino.spi.security.AccessDeniedException.denyExecuteTableProcedure;
import static io.trino.spi.security.AccessDeniedException.denyGrantRoles;
import static io.trino.spi.security.AccessDeniedException.denyGrantSchemaPrivilege;
import static io.trino.spi.security.AccessDeniedException.denyGrantTablePrivilege;
import static io.trino.spi.security.AccessDeniedException.denyInsertTable;
import static io.trino.spi.security.AccessDeniedException.denyRefreshMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyRenameColumn;
import static io.trino.spi.security.AccessDeniedException.denyRenameMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyRenameSchema;
import static io.trino.spi.security.AccessDeniedException.denyRenameTable;
import static io.trino.spi.security.AccessDeniedException.denyRenameView;
import static io.trino.spi.security.AccessDeniedException.denyRevokeRoles;
import static io.trino.spi.security.AccessDeniedException.denyRevokeSchemaPrivilege;
import static io.trino.spi.security.AccessDeniedException.denyRevokeTablePrivilege;
import static io.trino.spi.security.AccessDeniedException.denySelectColumns;
import static io.trino.spi.security.AccessDeniedException.denySetMaterializedViewProperties;
import static io.trino.spi.security.AccessDeniedException.denySetRole;
import static io.trino.spi.security.AccessDeniedException.denySetSchemaAuthorization;
import static io.trino.spi.security.AccessDeniedException.denySetTableAuthorization;
import static io.trino.spi.security.AccessDeniedException.denySetTableProperties;
import static io.trino.spi.security.AccessDeniedException.denySetViewAuthorization;
import static io.trino.spi.security.AccessDeniedException.denyShowCurrentRoles;
import static io.trino.spi.security.AccessDeniedException.denyShowRoleGrants;
import static io.trino.spi.security.AccessDeniedException.denyShowRoles;
import static io.trino.spi.security.AccessDeniedException.denyTruncateTable;
import static io.trino.spi.security.AccessDeniedException.denyUpdateTableColumns;
import static java.lang.String.format;
import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Connector access control which uses existing Ranger policies for authorizations
 */

public class RangerBasedAccessControl
        implements ConnectorAccessControl
{
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final JsonCodec<Users> USER_INFO_CODEC = jsonCodec(Users.class);
    private static final JsonCodec<List<String>> ROLES_INFO_CODEC = listJsonCodec(String.class);

    private final RangerAuthorizer rangerAuthorizer;
    private final Supplier<Map<String, Set<String>>> userRolesMapping;
    private final Supplier<Map<String, Set<String>>> userGroupsMapping;
    private final Supplier<ServicePolicies> servicePolicies;
    private final HttpClient httpClient;
    private final String catalogName;

    @Inject
    public RangerBasedAccessControl(RangerBasedAccessControlConfig config, CatalogName catalogName, @ForRangerInfo HttpClient httpClient)
    {
        requireNonNull(config, "config is null");
        requireNonNull(config.getRangerHttpEndPoint(), "Ranger service http end point is null");
        requireNonNull(config.getRangerHiveServiceName(), "Ranger hive service name is null");
        this.httpClient = requireNonNull(httpClient, "httpClient is null");
        this.catalogName = requireNonNull(catalogName, "catalogName is null").toString();

        try {
            servicePolicies = memoizeWithExpiration(
                    () -> getHiveServicePolicies(config),
                    config.getRefreshPeriod().toMillis(),
                    MILLISECONDS);

            userGroupsMapping = memoizeWithExpiration(
                    () -> getUserGroupsMappings(config),
                    config.getRefreshPeriod().toMillis(),
                    MILLISECONDS);

            userRolesMapping = memoizeWithExpiration(
                    () -> getRolesForUserList(config),
                    config.getRefreshPeriod().toMillis(),
                    MILLISECONDS);

            rangerAuthorizer = new RangerAuthorizer(servicePolicies, config);
        }
        catch (Exception e) {
            throw new RuntimeException("Unable to query ranger service ", e);
        }
    }

    private ServicePolicies getHiveServicePolicies(RangerBasedAccessControlConfig config)
    {
        URI uri = uriBuilderFrom(URI.create(config.getRangerHttpEndPoint()))
                .appendPath(RANGER_REST_POLICY_MGR_DOWNLOAD_URL + "/" + config.getRangerHiveServiceName())
                .build();
        Request request = setContentTypeHeaders(prepareGet())
                .setUri(uri)
                .build();
        try {
            return OBJECT_MAPPER.readValue(httpClient.execute(request, createStringResponseHandler()).getBody(), ServicePolicies.class);
        }
        catch (IOException e) {
            throw new TrinoException(HIVE_RANGER_SERVER_ERROR, format("Unable to fetch policies from %s hive service end point", config.getRangerHiveServiceName()));
        }
    }

    private Users getUsers(RangerBasedAccessControlConfig config)
    {
        URI uri = uriBuilderFrom(URI.create(config.getRangerHttpEndPoint()))
                .appendPath(RANGER_REST_USER_GROUP_URL)
                .build();
        Request request = setContentTypeHeaders(prepareGet())
                .setUri(uri)
                .build();

        return httpClient.execute(request, createJsonResponseHandler(USER_INFO_CODEC));
    }

    private static Request.Builder setContentTypeHeaders(Request.Builder requestBuilder)
    {
        return requestBuilder
                .setHeader("Accept", "application/json");
    }

    private Map<String, Set<String>> getRolesForUserList(RangerBasedAccessControlConfig config)
    {
        Users users = getUsers(config);
        ImmutableMap.Builder<String, Set<String>> userRolesMapping = ImmutableMap.builder();
        for (VXUser vxUser : users.getvXUsers()) {
            userRolesMapping.put(vxUser.getName(), getRolesForUser(vxUser.getName(), config));
        }
        return userRolesMapping.buildOrThrow();
    }

    private Set<String> getRolesForUser(String userName, RangerBasedAccessControlConfig config)
    {
        URI uri = uriBuilderFrom(URI.create(config.getRangerHttpEndPoint()))
                .appendPath(RANGER_REST_USER_ROLES_URL + "/" + userName)
                .build();
        Request request = setContentTypeHeaders(prepareGet())
                .setUri(uri)
                .build();

        return ImmutableSet.copyOf(httpClient.execute(request, createJsonResponseHandler(ROLES_INFO_CODEC)));
    }

    private Map<String, Set<String>> getUserGroupsMappings(RangerBasedAccessControlConfig config)
    {
        Users users = getUsers(config);
        ImmutableMap.Builder<String, Set<String>> userGroupsMapping = ImmutableMap.builder();
        for (VXUser vxUser : users.getvXUsers()) {
            if (!(isNull(vxUser.getGroupNameList()) || vxUser.getGroupNameList().isEmpty())) {
                userGroupsMapping.put(vxUser.getName(), ImmutableSet.copyOf(vxUser.getGroupNameList()));
            }
        }
        return userGroupsMapping.buildOrThrow();
    }

//    private Set<String> getGroupsForUser(String username)
//    {
//        try {
//            return userGroupsMapping.get().get(username);
//        }
//        catch (Exception ex) {
//            throw new TrinoException(HIVE_RANGER_SERVER_ERROR, "Unable to fetch user groups information from ranger", ex);
//        }
//    }

    private Set<String> getRolesForUser(String username)
    {
        try {
            return userRolesMapping.get().get(username);
        }
        catch (Exception ex) {
            throw new TrinoException(HIVE_RANGER_SERVER_ERROR, "Unable to fetch user roles information from ranger", ex);
        }
    }

    enum HiveAccessType
    {
        NONE, CREATE, ALTER, DROP, INDEX, LOCK, SELECT, UPDATE, USE, ALL, ADMIN
    }

    private boolean checkAccess(ConnectorSecurityContext context, SchemaTableName tableName, String column, HiveAccessType accessType)
    {
        var user = context.getIdentity().getUser();
        return rangerAuthorizer.authorizeHiveResource(tableName.getSchemaName(), tableName.getTableName(), column,
                accessType.toString(), user, context.getIdentity().getGroups(), getRolesForUser(user));
    }

    private boolean checkAccess(ConnectorSecurityContext context, SchemaRoutineName routineName, String column, HiveAccessType accessType)
    {
        var user = context.getIdentity().getUser();
        return rangerAuthorizer.authorizeHiveResource(routineName.getSchemaName(), routineName.getRoutineName(), column,
                accessType.toString(), user, context.getIdentity().getGroups(), getRolesForUser(user));
    }

    /**
     * Check if identity is allowed to create the specified schema with properties.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateSchema(ConnectorSecurityContext context, String schemaName, Map<String, Object> properties)
    {
        var user = context.getIdentity().getUser();
        if (!rangerAuthorizer.authorizeHiveResource(schemaName, null, null,
                HiveAccessType.CREATE.toString(), user, context.getIdentity().getGroups(), getRolesForUser(user))) {
            denyCreateSchema(schemaName, format("Access denied - User [ %s ] does not have [CREATE] " +
                    "privilege on [ %s ] ", user, schemaName));
        }
    }

    /**
     * Check if identity is allowed to drop the specified schema.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropSchema(ConnectorSecurityContext context, String schemaName)
    {
        var user = context.getIdentity().getUser();
        if (!rangerAuthorizer.authorizeHiveResource(schemaName, null, null,
                HiveAccessType.DROP.toString(), user, context.getIdentity().getGroups(), getRolesForUser(user))) {
            denyDropSchema(schemaName, format("Access denied - User [ %s ] does not have [DROP] " +
                    "privilege on [ %s ] ", user, schemaName));
        }
    }

    /**
     * Check if identity is allowed to rename the specified schema.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameSchema(ConnectorSecurityContext context, String schemaName, String newSchemaName)
    {
        //Can't rename Hive schemas
        denyRenameSchema(schemaName, newSchemaName);
    }

    /**
     * Check if identity is allowed to change the specified schema's user/role.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetSchemaAuthorization(ConnectorSecurityContext context, String schemaName, TrinoPrincipal principal)
    {
        //Can't change authorization in Ranger
        denySetSchemaAuthorization(schemaName, principal);
    }

    /**
     * Check if identity is allowed to execute SHOW SCHEMAS.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterSchemas} method must handle filter all results for unauthorized users,
     * since there are multiple ways to list schemas.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowSchemas(ConnectorSecurityContext context)
    {
        //Always allowed?
        //denyShowSchemas();
    }

    /**
     * Filter the list of schemas to those visible to the identity.
     */
    @Override
    public Set<String> filterSchemas(ConnectorSecurityContext context, Set<String> schemaNames)
    {
        var user = context.getIdentity().getUser();
        Set<String> allowedSchemas = new HashSet<>();
        Set<String> groups = context.getIdentity().getGroups();
        Set<String> roles = getRolesForUser(user);

        for (String schema : schemaNames) {
            if (rangerAuthorizer.authorizeHiveResource(schema, null, null, RangerPolicyEngine.ANY_ACCESS, user, groups, roles)) {
                allowedSchemas.add(schema);
            }
        }
        return allowedSchemas;
    }

    /**
     * Check if identity is allowed to execute SHOW CREATE SCHEMA.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowCreateSchema(ConnectorSecurityContext context, String schemaName)
    {
        //Always allowed?
        //denyShowCreateSchema(schemaName);
    }

    /**
     * Check if identity is allowed to execute SHOW CREATE TABLE, SHOW CREATE VIEW or SHOW CREATE MATERIALIZED VIEW
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowCreateTable(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        //Always allowed?
        //denyShowCreateTable(tableName.toString(), null);
    }

    /**
     * Check if identity is allowed to create the specified table with properties.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateTable(ConnectorSecurityContext context, SchemaTableName tableName, Map<String, Object> properties)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.CREATE)) {
            denyCreateTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [CREATE] " +
                    "privilege on [ %s ] ", context.getIdentity().getUser(), tableName.getSchemaName()));
        }
    }

    /**
     * Check if identity is allowed to drop the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropTable(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.DROP)) {
            denyDropTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [DROP] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to rename the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameTable(ConnectorSecurityContext context, SchemaTableName tableName, SchemaTableName newTableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyRenameTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to set properties to the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetTableProperties(ConnectorSecurityContext context, SchemaTableName tableName, Map<String, Optional<Object>> properties)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denySetTableProperties(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to comment the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetTableComment(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyCommentTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to comment the specified view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetViewComment(ConnectorSecurityContext context, SchemaTableName viewName)
    {
        if (!checkAccess(context, viewName, null, HiveAccessType.ALTER)) {
            denyCommentView(viewName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), viewName.getSchemaName(), viewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to comment the column in the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetColumnComment(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyCommentColumn(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to show metadata of tables by executing SHOW TABLES, SHOW GRANTS etc..
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterTables} method must filter all results for unauthorized users,
     * since there are multiple ways to list tables.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowTables(ConnectorSecurityContext context, String schemaName)
    {
        //Always allowed
        //denyShowTables(schemaName);
    }

    /**
     * Filter the list of tables and views to those visible to the identity.
     */
    @Override
    public Set<SchemaTableName> filterTables(ConnectorSecurityContext context, Set<SchemaTableName> tableNames)
    {
        var user = context.getIdentity().getUser();
        Set<SchemaTableName> allowedTables = new HashSet<>();
        Set<String> groups = context.getIdentity().getGroups();
        Set<String> roles = getRolesForUser(user);

        for (SchemaTableName table : tableNames) {
            if (rangerAuthorizer.authorizeHiveResource(table.getSchemaName(), table.getTableName(), null, RangerPolicyEngine.ANY_ACCESS, user, groups, roles)) {
                allowedTables.add(table);
            }
        }
        return allowedTables;
    }

    /**
     * Check if identity is allowed to show columns of tables by executing SHOW COLUMNS, DESCRIBE etc.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterColumns} method must filter all results for unauthorized users,
     * since there are multiple ways to list columns.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowColumns(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        //Always allowed?
//        if (!checkAccess(context, tableName, null, HiveAccessType.USE)) {
//            denyShowColumns(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
//                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
//        }
    }

    /**
     * Filter lists of columns of multiple tables to those visible to the identity.
     */
    @Override
    public Map<SchemaTableName, Set<String>> filterColumns(ConnectorSecurityContext context, Map<SchemaTableName, Set<String>> tableColumns)
    {
        var user = context.getIdentity().getUser();
        Map<SchemaTableName, Set<String>> allowedColumns = new HashMap<>();
        Set<String> groups = context.getIdentity().getGroups();
        Set<String> roles = getRolesForUser(user);

        for (SchemaTableName table : tableColumns.keySet()) {
            Set<String> allowedColumnsForTable = new HashSet<>();
            for (String column : tableColumns.get(table)) {
                if (rangerAuthorizer.authorizeHiveResource(table.getSchemaName(), table.getTableName(), column, RangerPolicyEngine.ANY_ACCESS, user, groups, roles)) {
                    allowedColumnsForTable.add(column);
                }
            }
            allowedColumns.put(table, allowedColumnsForTable);
        }
        return allowedColumns;
    }

    /**
     * Check if identity is allowed to add columns to the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanAddColumn(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyAddColumn(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to alter columns for the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanAlterColumn(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyAlterColumn(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to drop columns from the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropColumn(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyDropColumn(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to change the specified table's user/role.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetTableAuthorization(ConnectorSecurityContext context, SchemaTableName tableName, TrinoPrincipal principal)
    {
        //Never allowed
        denySetTableAuthorization(tableName.toString(), principal);
    }

    /**
     * Check if identity is allowed to rename a column in the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameColumn(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.ALTER)) {
            denyRenameColumn(tableName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to select from the specified columns in a relation.  The column set can be empty.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSelectFromColumns(ConnectorSecurityContext context, SchemaTableName tableName, Set<String> columnNames)
    {
        Set<String> deniedColumns = new HashSet<>();
        for (String column : columnNames) {
            if (!checkAccess(context, tableName, column, HiveAccessType.SELECT)) {
                deniedColumns.add(column);
            }
        }
        if (deniedColumns.size() > 0) {
            denySelectColumns(tableName.getTableName(), columnNames, format("Access denied - User [ %s ] does not have [SELECT] " +
                    "privilege on all mentioned columns of [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to insert into the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanInsertIntoTable(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.UPDATE)) {
            denyInsertTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [UPDATE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to delete from the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDeleteFromTable(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.UPDATE)) {
            denyDeleteTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [UPDATE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to truncate the specified table in this catalog.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanTruncateTable(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.UPDATE)) {
            denyTruncateTable(tableName.getTableName(), format("Access denied - User [ %s ] does not have [UPDATE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to update the supplied columns in the specified table in this catalog.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanUpdateTableColumns(ConnectorSecurityContext context, SchemaTableName tableName, Set<String> updatedColumns)
    {
        for (String column : updatedColumns) {
            if (!checkAccess(context, tableName, column, HiveAccessType.UPDATE)) {
                denyUpdateTableColumns(tableName.toString(), updatedColumns, format("Access denied - User [ %s ] does not have [UPDATE] " +
                        "privilege on [ %s/%s.%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName(), column));
            }
        }
    }

    /**
     * Check if identity is allowed to create the specified view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateView(ConnectorSecurityContext context, SchemaTableName viewName)
    {
        if (!checkAccess(context, viewName, null, HiveAccessType.CREATE)) {
            denyCreateView(viewName.getTableName(), format("Access denied - User [ %s ] does not have [CREATE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), viewName.getSchemaName(), viewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to rename the specified view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameView(ConnectorSecurityContext context, SchemaTableName viewName, SchemaTableName newViewName)
    {
        if (!checkAccess(context, viewName, null, HiveAccessType.ALTER)) {
            denyRenameView(viewName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), viewName.getSchemaName(), viewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to change the specified view's user/role.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetViewAuthorization(ConnectorSecurityContext context, SchemaTableName viewName, TrinoPrincipal principal)
    {
        //Always denied
        denySetViewAuthorization(viewName.toString(), principal);
    }

    /**
     * Check if identity is allowed to drop the specified view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropView(ConnectorSecurityContext context, SchemaTableName viewName)
    {
        if (!checkAccess(context, viewName, null, HiveAccessType.DROP)) {
            denyDropView(viewName.getTableName(), format("Access denied - User [ %s ] does not have [DROP] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), viewName.getSchemaName(), viewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to create a view that selects from the specified columns in a relation.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateViewWithSelectFromColumns(ConnectorSecurityContext context, SchemaTableName tableName, Set<String> columnNames)
    {
        if (!checkAccess(context, tableName, null, HiveAccessType.CREATE)) {
            denyCreateView(tableName.getTableName(), format("Access denied - User [ %s ] does not have [CREATE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), tableName.getSchemaName(), tableName.getTableName()));
        }

        Set<String> deniedColumns = new HashSet<>();
        for (String column : columnNames) {
            if (!checkAccess(context, tableName, column, HiveAccessType.SELECT)) {
                deniedColumns.add(column);
            }
        }
        if (deniedColumns.size() > 0) {
            denyCreateViewWithSelect(tableName.getTableName(), context.getIdentity());
        }
    }

    /**
     * Check if identity is allowed to create the specified materialized view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateMaterializedView(ConnectorSecurityContext context, SchemaTableName materializedViewName, Map<String, Object> properties)
    {
        if (!checkAccess(context, materializedViewName, null, HiveAccessType.CREATE)) {
            denyCreateMaterializedView(materializedViewName.getTableName(), format("Access denied - User [ %s ] does not have [CREATE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), materializedViewName.getSchemaName(), materializedViewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to refresh the specified materialized view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRefreshMaterializedView(ConnectorSecurityContext context, SchemaTableName materializedViewName)
    {
        if (!checkAccess(context, materializedViewName, null, HiveAccessType.ALTER)) {
            denyRefreshMaterializedView(materializedViewName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), materializedViewName.getSchemaName(), materializedViewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to set the properties of the specified materialized view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetMaterializedViewProperties(ConnectorSecurityContext context, SchemaTableName materializedViewName, Map<String, Optional<Object>> properties)
    {
        if (!checkAccess(context, materializedViewName, null, HiveAccessType.ALTER)) {
            denySetMaterializedViewProperties(materializedViewName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), materializedViewName.getSchemaName(), materializedViewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to drop the specified materialized view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropMaterializedView(ConnectorSecurityContext context, SchemaTableName materializedViewName)
    {
        if (!checkAccess(context, materializedViewName, null, HiveAccessType.DROP)) {
            denyDropMaterializedView(materializedViewName.getTableName(), format("Access denied - User [ %s ] does not have [DROP] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), materializedViewName.getSchemaName(), materializedViewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to rename the specified materialized view.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameMaterializedView(ConnectorSecurityContext context, SchemaTableName viewName, SchemaTableName newViewName)
    {
        if (!checkAccess(context, viewName, null, HiveAccessType.ALTER)) {
            denyRenameMaterializedView(viewName.getTableName(), format("Access denied - User [ %s ] does not have [ALTER] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), viewName.getSchemaName(), viewName.getTableName()));
        }
    }

    /**
     * Check if identity is allowed to set the specified property.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetCatalogSessionProperty(ConnectorSecurityContext context, String propertyName)
    {
        //Always allowed
        //denySetCatalogSessionProperty(propertyName);
    }

    /**
     * Check if identity is allowed to grant to any other user the specified privilege on the specified schema.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanGrantSchemaPrivilege(ConnectorSecurityContext context, Privilege privilege, String schemaName, TrinoPrincipal grantee, boolean grantOption)
    {
        //Always denied
        denyGrantSchemaPrivilege(privilege.toString(), schemaName);
    }

    /**
     * Check if identity is allowed to deny to any other user the specified privilege on the specified schema.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDenySchemaPrivilege(ConnectorSecurityContext context, Privilege privilege, String schemaName, TrinoPrincipal grantee)
    {
        //Always denies
        denyDenySchemaPrivilege(privilege.toString(), schemaName);
    }

    @Override
    public void checkCanRevokeSchemaPrivilege(ConnectorSecurityContext context, Privilege privilege, String schemaName, TrinoPrincipal revokee, boolean grantOption)
    {
        //Always denied
        denyRevokeSchemaPrivilege(privilege.toString(), schemaName);
    }

    /**
     * Check if identity is allowed to grant to any other user the specified privilege on the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanGrantTablePrivilege(ConnectorSecurityContext context, Privilege privilege, SchemaTableName tableName, TrinoPrincipal grantee, boolean grantOption)
    {
        //Always denied
        denyGrantTablePrivilege(privilege.toString(), tableName.toString());
    }

    /**
     * Check if identity is allowed to deny to any other user the specified privilege on the specified table.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDenyTablePrivilege(ConnectorSecurityContext context, Privilege privilege, SchemaTableName tableName, TrinoPrincipal grantee)
    {
        //Always denied
        denyDenyTablePrivilege(privilege.toString(), tableName.toString());
    }

    /**
     * Check if identity is allowed to revoke the specified privilege on the specified table from any user.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRevokeTablePrivilege(ConnectorSecurityContext context, Privilege privilege, SchemaTableName tableName, TrinoPrincipal revokee, boolean grantOption)
    {
        //Always denied
        denyRevokeTablePrivilege(privilege.toString(), tableName.toString());
    }

    @Override
    public void checkCanCreateRole(ConnectorSecurityContext context, String role, Optional<TrinoPrincipal> grantor)
    {
        //Always denied
        denyCreateRole(role);
    }

    @Override
    public void checkCanDropRole(ConnectorSecurityContext context, String role)
    {
        //Always denied
        denyDropRole(role);
    }

    @Override
    public void checkCanGrantRoles(ConnectorSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor)
    {
        //Always denied
        denyGrantRoles(roles, grantees);
    }

    @Override
    public void checkCanRevokeRoles(ConnectorSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor)
    {
        //Always denied
        denyRevokeRoles(roles, grantees);
    }

    @Override
    public void checkCanSetRole(ConnectorSecurityContext context, String role)
    {
        //Always denied
        denySetRole(role);
    }

    /**
     * Check if identity is allowed to show roles.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowRoles(ConnectorSecurityContext context)
    {
        //Always denied
        denyShowRoles();
    }

    /**
     * Check if identity is allowed to show current roles.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowCurrentRoles(ConnectorSecurityContext context)
    {
        //Always denied
        denyShowCurrentRoles();
    }

    /**
     * Check if identity is allowed to show its own role grants.
     *
     * @throws io.trino.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowRoleGrants(ConnectorSecurityContext context)
    {
        //Always denied
        denyShowRoleGrants();
    }

    @Override
    public void checkCanExecuteProcedure(ConnectorSecurityContext context, SchemaRoutineName procedure)
    {
        if (!checkAccess(context, procedure, null, HiveAccessType.USE)) {
            denyExecuteProcedure(procedure.getRoutineName(), format("Access denied - User [ %s ] does not have [USE] " +
                    "privilege on [ %s/%s ] ", context.getIdentity().getUser(), procedure.getSchemaName(), procedure.getRoutineName()));
        }
    }

    @Override
    public void checkCanExecuteTableProcedure(ConnectorSecurityContext context, SchemaTableName tableName, String procedure)
    {
        //Does Hive even have table procedures?
        denyExecuteTableProcedure(tableName.toString(), procedure);
    }

    /**
     * Is the identity allowed to execute the specified function?
     */
    @Override
    public boolean canExecuteFunction(ConnectorSecurityContext context, SchemaRoutineName function)
    {
        //TODO function kind
        return checkAccess(context, function, null, HiveAccessType.USE);
    }

    /**
     * Is identity allowed to create a view that executes the specified function?
     */
    @Override
    public boolean canCreateViewWithExecuteFunction(ConnectorSecurityContext context, SchemaRoutineName function)
    {
        return checkAccess(context, function, null, HiveAccessType.USE);
    }

    /**
     * Check if identity is allowed to show functions by executing SHOW FUNCTIONS.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterFunctions} method must filter all results for unauthorized users,
     * since there are multiple ways to list functions.
     *
     * @throws AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowFunctions(ConnectorSecurityContext context, String schemaName)
    {
        //Always allowed
        //denyShowFunctions(schemaName);
    }

    /**
     * Filter the list of functions to those visible to the identity.
     */
    @Override
    public Set<SchemaFunctionName> filterFunctions(ConnectorSecurityContext context, Set<SchemaFunctionName> functionNames)
    {
        var user = context.getIdentity().getUser();
        Set<SchemaFunctionName> allowedFunctions = new HashSet<>();
        Set<String> groups = context.getIdentity().getGroups();
        Set<String> roles = getRolesForUser(user);

        for (SchemaFunctionName table : functionNames) {
            if (rangerAuthorizer.authorizeHiveResource(table.getSchemaName(), table.getFunctionName(), null, RangerPolicyEngine.ANY_ACCESS, user, groups, roles)) {
                allowedFunctions.add(table);
            }
        }
        return allowedFunctions;
    }

    /**
     * Check if identity is allowed to create the specified function.
     *
     * @throws AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateFunction(ConnectorSecurityContext context, SchemaRoutineName function)
    {
        //Always denied
        denyCreateFunction(function.toString());
    }

    /**
     * Check if identity is allowed to drop the specified function.
     *
     * @throws AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropFunction(ConnectorSecurityContext context, SchemaRoutineName function)
    {
        //Always denied
        denyDropFunction(function.toString());
    }

    /**
     * Get row filters associated with the given table and identity.
     * <p>
     * Each filter must be a scalar SQL expression of boolean type over the columns in the table.
     *
     * @return the list of filters, or empty list if not applicable
     */
    @Override
    public List<ViewExpression> getRowFilters(ConnectorSecurityContext context, SchemaTableName tableName)
    {
        var user = context.getIdentity().getUser();
        Set<String> groups = context.getIdentity().getGroups();
        Set<String> roles = getRolesForUser(user);
        var filter = rangerAuthorizer.getRowFilter(tableName.getSchemaName(), tableName.getTableName(), user, groups, roles);

        if (isNullOrEmpty(filter)) {
            return List.of();
        }
        else {
            return List.of(ViewExpression.builder()
                    .catalog(catalogName)
                    .schema(tableName.getSchemaName())
                    .identity(user)
                    .expression(filter)
                    .build());
        }
    }

    /**
     * Get column mask associated with the given table, column and identity.
     * <p>
     * The mask must be a scalar SQL expression of a type coercible to the type of the column being masked. The expression
     * must be written in terms of columns in the table.
     *
     * @return the mask if present, or empty if not applicable
     */
    @Override
    public Optional<ViewExpression> getColumnMask(ConnectorSecurityContext context, SchemaTableName tableName, String columnName, Type type)
    {
        var user = context.getIdentity().getUser();
        Set<String> groups = context.getIdentity().getGroups();
        Set<String> roles = getRolesForUser(user);
        var mask = rangerAuthorizer.getColumnMask(tableName.getSchemaName(), tableName.getTableName(), columnName, user, groups, roles);

        if (isNullOrEmpty(mask)) {
            return Optional.empty();
        }
        else {
            mask = mask.replace("{col}", columnName).replace("{type}", type.getDisplayName());
            return Optional.of(ViewExpression.builder()
                    .catalog(catalogName)
                    .schema(tableName.getSchemaName())
                    .identity(user)
                    .expression(mask)
                    .build());
        }
    }
}
