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

import com.google.inject.Binder;
import com.google.inject.Scopes;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.trino.plugin.hive.security.AccessControlMetadata;
import io.trino.plugin.hive.security.AccessControlMetadataFactory;
import io.trino.plugin.hive.security.SqlStandardAccessControlMetadata;
import io.trino.plugin.hive.security.SqlStandardAccessControlMetadataMetastore;
import io.trino.spi.connector.ConnectorAccessControl;

import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;

public class RangerBasedAccessControlModule
        extends AbstractConfigurationAwareModule
{
    @Override
    public void setup(Binder binder)
    {
        configBinder(binder).bindConfig(RangerBasedAccessControlConfig.class);
        binder.bind(ConnectorAccessControl.class).to(RangerBasedAccessControl.class).in(Scopes.SINGLETON);
        binder.bind(AccessControlMetadataFactory.class).to(RangerBasedAccessControlModule.RangerBasedAccessControlMetadataFactory.class);

        RangerBasedAccessControlConfig rangerConfig = buildConfigObject(RangerBasedAccessControlConfig.class);
        if (rangerConfig.getBasicAuthUser() != null && rangerConfig.getBasicAuthPassword() != null) {
            httpClientBinder(binder).bindHttpClient("ranger", ForRangerInfo.class)
//                    .withConfigDefaults(config -> config.setAuthenticationEnabled(false))
                    .withFilter(RangerBasicAuthHttpRequestFilter.class);
        }
        else {
            httpClientBinder(binder).bindHttpClient("ranger", ForRangerInfo.class);
        }
    }

    private static final class RangerBasedAccessControlMetadataFactory
            implements AccessControlMetadataFactory
    {
        @Override
        public AccessControlMetadata create(SqlStandardAccessControlMetadataMetastore metastore)
        {
            return new SqlStandardAccessControlMetadata(metastore);
        }
    }
}
