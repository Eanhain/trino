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
package io.trino.plugin.singlestore;

import io.trino.Session;
import io.trino.spi.type.TimeZoneKey;
import io.trino.testing.QueryRunner;
import io.trino.testing.TestingSession;
import io.trino.testing.datatype.SqlDataTypeTest;
import org.junit.jupiter.api.Test;

import java.time.ZoneId;

import static io.trino.spi.type.DateType.DATE;
import static java.time.ZoneOffset.UTC;

final class TestSingleStoreTypeMapping
        extends BaseSingleStoreTypeMapping
{
    @Override
    protected QueryRunner createQueryRunner()
            throws Exception
    {
        singleStoreServer = closeAfterClass(new TestingSingleStoreServer());
        return SingleStoreQueryRunner.builder(singleStoreServer).build();
    }

    @Test
    void testOlderDate()
    {
        testOlderDate(UTC);
        testOlderDate(ZoneId.systemDefault());
        // no DST in 1970, but has DST in later years (e.g. 2018)
        testOlderDate(ZoneId.of("Europe/Vilnius"));
        // minutes offset change since 1970-01-01, no DST
        testOlderDate(ZoneId.of("Asia/Kathmandu"));
        testOlderDate(TestingSession.DEFAULT_TIME_ZONE_KEY.getZoneId());
    }

    private void testOlderDate(ZoneId sessionZone)
    {
        Session session = Session.builder(getSession())
                .setTimeZoneKey(TimeZoneKey.getTimeZoneKey(sessionZone.getId()))
                .build();

        SqlDataTypeTest.create()
                .addRoundTrip("date", "CAST('1000-01-01' AS date)", DATE, "DATE '1000-01-01'")
                .addRoundTrip("date", "CAST('1000-01-01' AS date)", DATE, "DATE '1000-01-01'")
                .execute(getQueryRunner(), session, singleStoreCreateAndInsert("tpch.test_date"))
                .execute(getQueryRunner(), session, trinoCreateAsSelect(session, "test_date"))
                .execute(getQueryRunner(), session, trinoCreateAsSelect("test_date"))
                .execute(getQueryRunner(), session, trinoCreateAndInsert(session, "test_date"))
                .execute(getQueryRunner(), session, trinoCreateAndInsert("test_date"));
    }
}
