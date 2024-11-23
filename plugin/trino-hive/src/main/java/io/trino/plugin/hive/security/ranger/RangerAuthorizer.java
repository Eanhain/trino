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

import io.airlift.log.Logger;
import io.trino.spi.TrinoException;
import org.apache.hadoop.conf.Configuration;
import org.apache.ranger.audit.provider.AuditProviderFactory;
import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngineOptions;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.apache.ranger.plugin.util.ServicePolicies;

import java.io.File;
import java.net.MalformedURLException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static com.google.common.base.Strings.isNullOrEmpty;
import static io.trino.plugin.hive.HiveErrorCode.HIVE_RANGER_SERVER_ERROR;
import static java.util.Locale.ENGLISH;
import static java.util.Objects.requireNonNull;

public class RangerAuthorizer
{
    private static final Logger log = Logger.get(RangerAuthorizer.class);
    private static final String KEY_DATABASE = "database";
    private static final String KEY_TABLE = "table";
    private static final String KEY_COLUMN = "column";
    private static final String CLUSTER_NAME = "Trino";
    private static final String HIVE = "hive";

    private final RangerBasePlugin plugin;
    private final Supplier<ServicePolicies> servicePolicies;
    private final AtomicReference<ServicePolicies> currentServicePolicies = new AtomicReference<>();

    public RangerAuthorizer(Supplier<ServicePolicies> servicePolicies, RangerBasedAccessControlConfig rangerBasedAccessControlConfig)
    {
        this.servicePolicies = requireNonNull(servicePolicies, "ServicePolicies is null");
        RangerPolicyEngineOptions rangerPolicyEngineOptions = new RangerPolicyEngineOptions();
        Configuration conf = new Configuration();
        rangerPolicyEngineOptions.configureDefaultRangerAdmin(conf, "hive");
        RangerPluginConfig rangerPluginConfig = new RangerPluginConfig(HIVE, rangerBasedAccessControlConfig.getRangerHiveServiceName(), HIVE, CLUSTER_NAME, null,
                rangerPolicyEngineOptions);
        plugin = new RangerBasePlugin(rangerPluginConfig);

        String hiveAuditPath = rangerBasedAccessControlConfig.getRangerHiveAuditPath();
        if (!isNullOrEmpty(hiveAuditPath)) {
            try {
                plugin.getConfig().addResource(new File(hiveAuditPath).toURI().toURL());
            }
            catch (MalformedURLException e) {
                log.error(e, "Invalid audit file is provided ");
            }
        }

        String hivePolicymgrSslPath = rangerBasedAccessControlConfig.getRangerHivePolicymgrSslPath();
        if (!isNullOrEmpty(hivePolicymgrSslPath)) {
            try {
                plugin.getConfig().addResource(new File(hivePolicymgrSslPath).toURI().toURL());
            }
            catch (MalformedURLException e) {
                log.error(e, "Invalid audit file is provided ");
            }
        }

        AuditProviderFactory providerFactory = AuditProviderFactory.getInstance();

        if (!providerFactory.isInitDone()) {
            if (plugin.getConfig().getProperties() != null) {
                providerFactory.init(plugin.getConfig().getProperties(), HIVE);
            }
            else {
                log.info("Audit subsystem is not initialized correctly. Please check audit configuration. ");
                log.info("No authorization audits will be generated. ");
            }
        }

        plugin.setResultProcessor(new RangerDefaultAuditHandler());
    }

    private void updateRangerPolicies()
    {
        ServicePolicies newServicePolicies = getRangerServicePolicies();
        ServicePolicies existingServicePolicies = currentServicePolicies.get();
        if (newServicePolicies != existingServicePolicies && currentServicePolicies.compareAndSet(existingServicePolicies, newServicePolicies)) {
            plugin.setPolicies(newServicePolicies);
        }
    }

    private ServicePolicies getRangerServicePolicies()
    {
        try {
            return servicePolicies.get();
        }
        catch (Exception ex) {
            throw new TrinoException(HIVE_RANGER_SERVER_ERROR, "Unable to fetch policy information from ranger", ex);
        }
    }

    public boolean authorizeHiveResource(String database, String table, String column, String accessType, String user, Set<String> userGroups, Set<String> userRoles)
    {
        updateRangerPolicies();
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        if (!isNullOrEmpty(database)) {
            resource.setValue(KEY_DATABASE, database);
        }

        if (!isNullOrEmpty(table)) {
            resource.setValue(KEY_TABLE, table);
        }

        if (!isNullOrEmpty(column)) {
            resource.setValue(KEY_COLUMN, column);
        }

        RangerAccessRequest request = new RangerAccessRequestImpl(resource, accessType.toLowerCase(ENGLISH), user, userGroups, userRoles);

        RangerAccessResult result = plugin.isAccessAllowed(request);

        return result != null && result.getIsAllowed();
    }

    public String getRowFilter(String database, String table, String user, Set<String> userGroups, Set<String> userRoles)
    {
        updateRangerPolicies();
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        if (!isNullOrEmpty(database)) {
            resource.setValue(KEY_DATABASE, database);
        }

        if (!isNullOrEmpty(table)) {
            resource.setValue(KEY_TABLE, table);
        }

        RangerAccessRequest request = new RangerAccessRequestImpl(resource, "select", user, userGroups, userRoles);

        RangerAccessResult result = plugin.evalRowFilterPolicies(request, null);

        if (result == null || !result.isRowFilterEnabled()) {
            return null;
        }
        else {
            String filter = result.getFilterExpr();
            log.debug("Received filter: %s", filter);
            return filter;
        }
    }

    public String getColumnMask(String database, String table, String column, String user, Set<String> userGroups, Set<String> userRoles)
    {
        updateRangerPolicies();
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        if (!isNullOrEmpty(database)) {
            resource.setValue(KEY_DATABASE, database);
        }

        if (!isNullOrEmpty(table)) {
            resource.setValue(KEY_TABLE, table);
        }

        if (!isNullOrEmpty(column)) {
            resource.setValue(KEY_COLUMN, column);
        }

        RangerAccessRequest request = new RangerAccessRequestImpl(resource, "select", user, userGroups, userRoles);

        RangerAccessResult result = plugin.evalDataMaskPolicies(request, null);

        if (result == null || !result.isMaskEnabled()) {
            return null;
        }
        else {
            String maskType = result.getMaskType();
            RangerServiceDef.RangerDataMaskTypeDef maskTypeDef = result.getMaskTypeDef();
            String transformer = null;

            if (maskTypeDef != null) {
                transformer = maskTypeDef.getTransformer();
            }

            return switch (maskType.toUpperCase(ENGLISH)) {
                case RangerPolicy.MASK_TYPE_NONE -> null;
                case RangerPolicy.MASK_TYPE_NULL -> "NULL";
                case "MASK" -> "cast(regexp_replace(regexp_replace(regexp_replace('{col}','\\p{Nd}','0'), '\\p{Ll}', 'x'), '\\p{Lu}', 'X') as {type})";
                case "MASK_SHOW_LAST_4" -> "cast(substr(regexp_replace({col},'.','x'),1,length({col})-4)||substr({col},greatest(length({col}),4)-3) as {type})";
                case "MASK_SHOW_FIRST_4" -> "cast(substr({col}},1,4)||substr(regexp_replace({col},'.','x'), 5) as {type}";
                case "MASK_HASH" -> "cast(to_hex(xxhash64(cast({col} as varbinary))) as {type})";
                case "MASK_DATE_SHOW_YEAR" -> "date_trunc('year',{col})";
                case RangerPolicy.MASK_TYPE_CUSTOM -> {
                    String maskedValue = result.getMaskedValue();
                    if (maskedValue == null) {
                        transformer = "NULL";
                    }
                    else {
                        transformer = maskedValue;
                    }
                    log.debug("Received MaskType: %s, Transformer: %s, MaskedValue: %s",
                            maskType, transformer, maskedValue);
                    yield transformer;
                }
                default -> throw new TrinoException(HIVE_RANGER_SERVER_ERROR, "Unexpected Ranger mask type");
            };
        }
    }
}
