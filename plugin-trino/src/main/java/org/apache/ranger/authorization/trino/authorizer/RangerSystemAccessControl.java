/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ranger.authorization.trino.authorizer;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.QueryId;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.Identity;
import io.trino.spi.security.TrinoPrincipal;
import io.trino.spi.security.Privilege;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;
import io.trino.spi.security.ViewExpression;
import io.trino.spi.type.Type;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;

import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Locale.ENGLISH;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

  final public static String RANGER_CONFIG_KEYTAB = "ranger.keytab";
  final public static String RANGER_CONFIG_PRINCIPAL = "ranger.principal";
  final public static String RANGER_CONFIG_USE_UGI = "ranger.use_ugi";
  final public static String RANGER_CONFIG_HADOOP_CONFIG = "ranger.hadoop_config";
  final public static String RANGER_TRINO_DEFAULT_HADOOP_CONF = "trino-ranger-site.xml";
  final public static String RANGER_TRINO_SERVICETYPE = "trino";
  final public static String RANGER_TRINO_APPID = "trino";

  final private RangerBasePlugin rangerPlugin;

  private boolean useUgi = false;

  public RangerSystemAccessControl(Map<String, String> config) {
    super();

    Configuration hadoopConf = new Configuration();
    if (config.get(RANGER_CONFIG_HADOOP_CONFIG) != null) {
      URL url =  hadoopConf.getResource(config.get(RANGER_CONFIG_HADOOP_CONFIG));
      if (url == null) {
        LOG.warn("Hadoop config " + config.get(RANGER_CONFIG_HADOOP_CONFIG) + " not found");
      } else {
        hadoopConf.addResource(url);
      }
    } else {
      URL url = hadoopConf.getResource(RANGER_TRINO_DEFAULT_HADOOP_CONF);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Trying to load Hadoop config from " + url + " (can be null)");
      }
      if (url != null) {
        hadoopConf.addResource(url);
      }
    }
    UserGroupInformation.setConfiguration(hadoopConf);

    if (config.get(RANGER_CONFIG_KEYTAB) != null && config.get(RANGER_CONFIG_PRINCIPAL) != null) {
      String keytab = config.get(RANGER_CONFIG_KEYTAB);
      String principal = config.get(RANGER_CONFIG_PRINCIPAL);

      LOG.info("Performing kerberos login with principal " + principal + " and keytab " + keytab);

      try {
        UserGroupInformation.loginUserFromKeytab(principal, keytab);
      } catch (IOException ioe) {
        LOG.error("Kerberos login failed", ioe);
        throw new RuntimeException(ioe);
      }
    }

    if (config.getOrDefault(RANGER_CONFIG_USE_UGI, "false").equalsIgnoreCase("true")) {
      useUgi = true;
    }

    rangerPlugin = new RangerBasePlugin(RANGER_TRINO_SERVICETYPE, RANGER_TRINO_APPID);
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
  }


  /** FILTERING AND DATA MASKING **/

  private RangerAccessResult getDataMaskResult(RangerTrinoAccessRequest request) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> getDataMaskResult(request=" + request + ")");
    }

    RangerAccessResult ret = rangerPlugin.evalDataMaskPolicies(request, null);

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== getDataMaskResult(request=" + request + "): ret=" + ret);
    }

    return ret;
  }

  private RangerAccessResult getRowFilterResult(RangerTrinoAccessRequest request) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> getRowFilterResult(request=" + request + ")");
    }

    RangerAccessResult ret = rangerPlugin.evalRowFilterPolicies(request, null);

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== getRowFilterResult(request=" + request + "): ret=" + ret);
    }

    return ret;
  }

  private boolean isDataMaskEnabled(RangerAccessResult result) {
    return result != null && result.isMaskEnabled();
  }

  private boolean isRowFilterEnabled(RangerAccessResult result) {
    return result != null && result.isRowFilterEnabled();
  }

  public Optional<ViewExpression> getRowFilter(Identity identity, CatalogSchemaTableName tableName) {
    RangerTrinoAccessRequest request = createAccessRequest(createResource(tableName), identity, TrinoAccessType.SELECT);
    RangerAccessResult result = getRowFilterResult(request);

    ViewExpression viewExpression = null;
    if (isRowFilterEnabled(result)) {
      String filter = result.getFilterExpr();
      viewExpression = ViewExpression.builder()
        .identity(identity.getUser())
        .catalog(tableName.getCatalogName())
        .schema(tableName.getSchemaTableName().getSchemaName())
        .expression(filter)
        .build();
    }
    return Optional.ofNullable(viewExpression);
  }

  public List<ViewExpression> getRowFilters(Identity identity, CatalogSchemaTableName tableName) {
    return getRowFilter(identity, tableName).map(ImmutableList::of).orElseGet(ImmutableList::of);
  }

  public Optional<ViewExpression> getColumnMask(Identity identity, CatalogSchemaTableName tableName, String columnName, Type type) {
    RangerTrinoAccessRequest request = createAccessRequest(
      createResource(tableName.getCatalogName(), tableName.getSchemaTableName().getSchemaName(),
        tableName.getSchemaTableName().getTableName(), Optional.of(columnName)),
      identity, TrinoAccessType.SELECT);
    RangerAccessResult result = getDataMaskResult(request);

    ViewExpression viewExpression = null;
    if (isDataMaskEnabled(result)) {
      String                maskType    = result.getMaskType();
      RangerServiceDef.RangerDataMaskTypeDef maskTypeDef = result.getMaskTypeDef();
      String transformer	= null;

      if (maskTypeDef != null) {
        transformer = maskTypeDef.getTransformer();
      }

      if(StringUtils.equalsIgnoreCase(maskType, RangerPolicy.MASK_TYPE_NULL)) {
        transformer = "NULL";
      } else if(StringUtils.equalsIgnoreCase(maskType, RangerPolicy.MASK_TYPE_CUSTOM)) {
        String maskedValue = result.getMaskedValue();

        if(maskedValue == null) {
          transformer = "NULL";
        } else {
          transformer = maskedValue;
        }
      }

      if(StringUtils.isNotEmpty(transformer)) {
        transformer = transformer.replace("{col}", columnName).replace("{type}", type.getDisplayName());
      }

      viewExpression = ViewExpression.builder()
        .identity(identity.getUser())
        .catalog(tableName.getCatalogName())
        .schema(tableName.getSchemaTableName().getSchemaName())
        .expression(transformer)
        .build();
      if (LOG.isDebugEnabled()) {
        LOG.debug("getColumnMask: user: %s, catalog: %s, schema: %s, transformer: %s");
      }

    }

    return Optional.ofNullable(viewExpression);
  }

  public List<ViewExpression> getColumnMasks(Identity identity, CatalogSchemaTableName tableName, String columnName, Type type) {
    return getColumnMask(identity, tableName, columnName, type).map(ImmutableList::of).orElseGet(ImmutableList::of);
  }

  public Set<String> filterCatalogs(Identity identity, Set<String> catalogs) {
    LOG.debug("==> RangerSystemAccessControl.filterCatalogs("+ catalogs + ")");
    Set<String> filteredCatalogs = new HashSet<>(catalogs.size());
    for (String catalog: catalogs) {
      if (hasPermission(createResource(catalog), identity, TrinoAccessType.SELECT)) {
        filteredCatalogs.add(catalog);
      }
    }
    return filteredCatalogs;
  }

  public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames) {
    LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
    Set<String> filteredSchemaNames = new HashSet<>(schemaNames.size());
    for (String schemaName: schemaNames) {
      if (hasPermission(createResource(catalogName, schemaName), identity, TrinoAccessType.SELECT)) {
        filteredSchemaNames.add(schemaName);
      }
    }
    return filteredSchemaNames;
  }

  public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames) {
    LOG.debug("==> RangerSystemAccessControl.filterTables(" + catalogName + ")");
    Set<SchemaTableName> filteredTableNames = new HashSet<>(tableNames.size());
    for (SchemaTableName tableName : tableNames) {
      RangerTrinoResource res = createResource(catalogName, tableName.getSchemaName(), tableName.getTableName());
      if (hasPermission(res, identity, TrinoAccessType.SELECT)) {
        filteredTableNames.add(tableName);
      }
    }
    return filteredTableNames;
  }

  /** PERMISSION CHECKS ORDERED BY SYSTEM, CATALOG, SCHEMA, TABLE, VIEW, COLUMN, QUERY, FUNCTIONS, PROCEDURES **/

  /** SYSTEM **/

  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, String propertyName) {
    SystemSecurityContext context = new SystemSecurityContext(identity, QueryId.valueOf("system-query"), Instant.now());
    if (!hasPermission(createSystemPropertyResource(propertyName), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanImpersonateUser(Identity identity, String userName) {
    SystemSecurityContext context = new SystemSecurityContext(identity, QueryId.valueOf("impersonate-query"), Instant.now());
    if (!hasPermission(createUserResource(userName), identity, TrinoAccessType.IMPERSONATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanImpersonateUser(" + userName + ") denied");
      AccessDeniedException.denyImpersonateUser(identity.getUser(), userName);
    }
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    // pass as it is deprecated
  }

  /** CATALOG **/
  public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName) {
    if (!hasPermission(createCatalogSessionResource(catalogName, propertyName), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetSystemSessionProperty(" + catalogName + ") denied");
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

  public void checkCanShowRoles(Identity identity) {
    //allow
  }

  public void checkCanShowCurrentRoles(Identity identity) {
    //allow
  }

  public void checkCanShowRoleGrants(Identity identity) {
    //allow
  }

  public boolean canAccessCatalog(SystemSecurityContext context, String catalogName) {
    boolean can = hasPermission(createResource(catalogName), context.getIdentity(), TrinoAccessType.USE);
    if (!can) {
      LOG.debug("RangerSystemAccessControl.canAccessCatalog(" + catalogName + ") denied");
    }
    return can;
  }
//  public boolean canAccessCatalog(Identity identity, String catalogName) {
//    boolean can = hasPermission(createResource(catalogName), identity, TrinoAccessType.USE);
//    if (!can) {
//      LOG.debug("RangerSystemAccessControl.canAccessCatalog(" + catalogName + ") denied");
//    }
//    return can;
////    if (!hasPermission(createResource(catalogName), identity, TrinoAccessType.USE)) {
////      LOG.debug("RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ") denied");
////      AccessDeniedException.denyCatalogAccess(catalogName);
////    }
//  }

  public void checkCanShowSchemas(Identity identity, String catalogName) {
    if (!hasPermission(createResource(catalogName), identity, TrinoAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
      AccessDeniedException.denyShowSchemas(catalogName);
    }
  }

  /** SCHEMA **/

  public void checkCanSetSchemaAuthorization(Identity identity, CatalogSchemaName schema, TrinoPrincipal principal) {
    if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, TrinoAccessType.GRANT)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetSchemaAuthorization(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denySetSchemaAuthorization(schema.getSchemaName(), principal);
    }
  }

  public void checkCanShowCreateSchema(Identity identity, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, TrinoAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowCreateSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyShowCreateSchema(schema.getSchemaName());
    }
  }

  /**
   * Create schema is evaluated on the level of the Catalog. This means that it is assumed you have permission
   * to create a schema when you have create rights on the catalog level
   */
  public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema, Map<String, Object> properties) {
    if (!hasPermission(createResource(schema.getCatalogName()), identity, TrinoAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  /**
   * This is evaluated against the schema name as ownership information is not available
   */
  public void checkCanDropSchema(Identity identity, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), identity, TrinoAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  /**
   * This is evaluated against the schema name as ownership information is not available
   */
  public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName) {
    RangerTrinoResource res = createResource(schema.getCatalogName(), schema.getSchemaName());
    if (!hasPermission(res, identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  /** TABLE **/

  public void checkCanShowTables(Identity identity, CatalogSchemaName schema) {
    if (!hasPermission(createResource(schema), identity, TrinoAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowTables(" + schema.toString() + ") denied");
      AccessDeniedException.denyShowTables(schema.toString());
    }
  }


  public void checkCanShowCreateTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowTables(" + table.toString() + ") denied");
      AccessDeniedException.denyShowCreateTable(table.toString());
    }
  }

  /**
   * Create table is verified on schema level
   */
  public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table, Map<String, Object> properties) {
    if (!hasPermission(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName()), identity, TrinoAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  public void checkCanDropTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    RangerTrinoResource res = createResource(table);
    if (!hasPermission(res, identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table) {
    RangerTrinoResource res = createResource(table);
    if (!hasPermission(res, identity, TrinoAccessType.INSERT)) {
      LOG.debug("RangerSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.DELETE)) {
      LOG.debug("RangerSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  public void checkCanTruncateTable(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.DELETE)) {
      LOG.debug("RangerSystemAccessControl.checkCanTruncateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyTruncateTable(table.getSchemaTableName().getTableName());
    }
  }

  public void checkCanGrantTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean withGrantOption) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.GRANT)) {
      LOG.debug("RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
    }
  }

  public void checkCanRevokeTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal revokee, boolean grantOptionFor) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.REVOKE)) {
      LOG.debug("RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
    }
  }

  public void checkCanSetTableComment(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetTableComment(" + table.toString() + ") denied");
      AccessDeniedException.denyCommentTable(table.toString());
    }
  }

  public void checkCanSetColumnComment(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetColumnComment(" + table.toString() + ") denied");
      AccessDeniedException.denyCommentColumn(table.toString());
    }
  }

  /**
   * Create view is verified on schema level
   */
  public void checkCanCreateView(Identity identity, CatalogSchemaTableName view) {
    if (!hasPermission(createResource(view.getCatalogName(), view.getSchemaTableName().getSchemaName()), identity, TrinoAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  public void checkCanDropView(Identity identity, CatalogSchemaTableName view) {
    if (!hasPermission(createResource(view), identity, TrinoAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
    }
  }

  public void checkCanSetViewAuthorization(Identity identity, CatalogSchemaTableName view, TrinoPrincipal principal){
    if (!hasPermission(createResource(view), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanSetViewAuthorization(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denySetViewAuthorization(view.toString(), principal);
    }
  }

  /**
   * This check equals the check for checkCanCreateView
   */
  public void checkCanCreateViewWithSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    try {
      checkCanCreateView(identity, table);
    } catch (AccessDeniedException ade) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
    }
  }

  /**
   *
   * check if materialized view can be created
   */
  public void checkCanCreateMaterializedView(Identity identity, CatalogSchemaTableName materializedView, Map<String, Object> properties) {
    if (!hasPermission(createResource(materializedView), identity, TrinoAccessType.CREATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanCreateMaterializedView( " + materializedView.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateMaterializedView(materializedView.getSchemaTableName().getTableName());
    }

  }

  public void checkCanDropMaterializedView(Identity identity, CatalogSchemaTableName materializedView) {
    if(!hasPermission(createResource(materializedView),identity,TrinoAccessType.DROP)){
      LOG.debug("RangerSystemAccessControl.checkCanDropMaterializedView(" + materializedView.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(materializedView.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated against the table name as ownership information is not available
   */
  public void checkCanRenameView(Identity identity, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
    if (!hasPermission(createResource(view), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameView(" + view.toString() + ") denied");
      AccessDeniedException.denyRenameView(view.toString(), newView.toString());
    }
  }

  /** COLUMN **/

  /**
   * This is evaluated on table level
   */
  public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table) {
    RangerTrinoResource res = createResource(table);
    if (!hasPermission(res, identity, TrinoAccessType.ALTER)) {
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table) {
    RangerTrinoResource res = createResource(table);
    if (!hasPermission(res, identity, TrinoAccessType.DROP)) {
      LOG.debug("RangerSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table) {
    RangerTrinoResource res = createResource(table);
    if (!hasPermission(res, identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  /**
   * This is evaluated on table level
   */
  public void checkCanShowColumns(Identity identity, CatalogSchemaTableName table) {
    if (!hasPermission(createResource(table), identity, TrinoAccessType.SHOW)) {
      LOG.debug("RangerSystemAccessControl.checkCanShowTables(" + table.toString() + ") denied");
      AccessDeniedException.denyShowColumns(table.toString());
    }
  }

  public void checkCanSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    for (RangerTrinoResource res : createResource(table, columns)) {
      if (!hasPermission(res, identity, TrinoAccessType.SELECT)) {
        LOG.debug("RangerSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
      }
    }
  }

  /**
   * This is a NOOP, no filtering is applied
   */
  public Set<String> filterColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    return columns;
  }

  /** QUERY **/

  /**
   * This is a NOOP. Everyone can execute a query
   * @param identity
   */
  @Override
  public void checkCanExecuteQuery(Identity identity) {
  }

  @Override
  public void checkCanViewQueryOwnedBy(Identity identity, Identity queryOwner) {
    SystemSecurityContext context = new SystemSecurityContext(identity, QueryId.valueOf("view-query"), Instant.now());
    if (!hasPermission(createUserResource(queryOwner.getUser()), identity, TrinoAccessType.IMPERSONATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanViewQueryOwnedBy(" + queryOwner.getUser() + ") denied");
      AccessDeniedException.denyImpersonateUser(identity.getUser(), queryOwner.getUser());
    }
  }

  /**
   * This is a NOOP, no filtering is applied
   */
  @Override
  public Collection<Identity> filterViewQueryOwnedBy(Identity identity, Collection<Identity> queryOwners) {
    return queryOwners;
  }

  @Override
  public void checkCanKillQueryOwnedBy(Identity identity, Identity queryOwner) {
    SystemSecurityContext context = new SystemSecurityContext(identity, QueryId.valueOf("kill-query"), Instant.now());
    if (!hasPermission(createUserResource(queryOwner.getUser()), identity, TrinoAccessType.IMPERSONATE)) {
      LOG.debug("RangerSystemAccessControl.checkCanKillQueryOwnedBy(" + queryOwner.getUser() + ") denied");
      AccessDeniedException.denyImpersonateUser(identity.getUser(), queryOwner.getUser());
    }
  }

  /** FUNCTIONS **/
  public void checkCanGrantExecuteFunctionPrivilege(Identity identity, String function, TrinoPrincipal grantee, boolean grantOption) {
    if (!hasPermission(createFunctionResource(function), identity, TrinoAccessType.GRANT)) {
      LOG.debug("RangerSystemAccessControl.checkCanGrantExecuteFunctionPrivilege(" + function + ") denied");
      AccessDeniedException.denyGrantExecuteFunctionPrivilege(function, identity, grantee);
    }
  }

  public boolean canExecuteFunction(Identity identity, CatalogSchemaRoutineName functionName) {
    boolean hasPermission = hasPermission(createFunctionResource(functionName.toString()), identity, TrinoAccessType.EXECUTE);
    if (!hasPermission) {
      LOG.debug("RangerSystemAccessControl.canExecuteFunction(" + functionName + ") denied");
    }
    return hasPermission;
  }

  /** PROCEDURES **/
  public void checkCanExecuteProcedure(Identity identity, CatalogSchemaRoutineName procedure) {
    if (!hasPermission(createProcedureResource(procedure), identity, TrinoAccessType.EXECUTE)) {
      LOG.debug("RangerSystemAccessControl.checkCanExecuteFunction(" + procedure.getSchemaRoutineName().getRoutineName() + ") denied");
      AccessDeniedException.denyExecuteProcedure(procedure.getSchemaRoutineName().getRoutineName());
    }
  }

  public void checkCanExecuteTableProcedure(Identity identity, CatalogSchemaTableName catalogSchemaTableName, String procedure)
  {
    if (!hasPermission(createResource(catalogSchemaTableName), identity, TrinoAccessType.ALTER)) {
      LOG.debug("RangerSystemAccessControl.checkCanExecuteFunction(" + procedure + ") denied");
      AccessDeniedException.denyExecuteTableProcedure(catalogSchemaTableName.toString(),procedure);
    }
  }

  /** HELPER FUNCTIONS **/

  private RangerTrinoAccessRequest createAccessRequest(RangerTrinoResource resource, Identity identity, TrinoAccessType accessType) {
    Set<String> userGroups = null;

    if (useUgi) {
      UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

      String[] groups = ugi != null ? ugi.getGroupNames() : null;

      if (groups != null && groups.length > 0) {
        userGroups = new HashSet<>(Arrays.asList(groups));
      }
    } else {
      userGroups = identity.getGroups();
    }

    RangerTrinoAccessRequest request = new RangerTrinoAccessRequest(
      resource,
      identity.getUser(),
      userGroups,
      accessType
    );

    return request;
  }

  private boolean hasPermission(RangerTrinoResource resource, Identity identity, TrinoAccessType accessType) {
    boolean ret = false;

    RangerTrinoAccessRequest request = createAccessRequest(resource, identity, accessType);

    RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
    if (result != null && result.getIsAllowed()) {
      ret = true;
    }

    return ret;
  }

  private static RangerTrinoResource createUserResource(String userName) {
    RangerTrinoResource res = new RangerTrinoResource();
    res.setValue(RangerTrinoResource.KEY_USER, userName);

    return res;
  }

  private static RangerTrinoResource createFunctionResource(String function) {
    RangerTrinoResource res = new RangerTrinoResource();
    res.setValue(RangerTrinoResource.KEY_FUNCTION, function);

    return res;
  }

  private static RangerTrinoResource createProcedureResource(CatalogSchemaRoutineName procedure) {
    RangerTrinoResource res = new RangerTrinoResource();
    res.setValue(RangerTrinoResource.KEY_CATALOG, procedure.getCatalogName());
    res.setValue(RangerTrinoResource.KEY_SCHEMA, procedure.getSchemaRoutineName().getSchemaName());
    res.setValue(RangerTrinoResource.KEY_PROCEDURE, procedure.getSchemaRoutineName().getRoutineName());

    return res;
  }

  private static RangerTrinoResource createCatalogSessionResource(String catalogName, String propertyName) {
    RangerTrinoResource res = new RangerTrinoResource();
    res.setValue(RangerTrinoResource.KEY_CATALOG, catalogName);
    res.setValue(RangerTrinoResource.KEY_SESSION_PROPERTY, propertyName);

    return res;
  }

  private static RangerTrinoResource createSystemPropertyResource(String property) {
    RangerTrinoResource res = new RangerTrinoResource();
    res.setValue(RangerTrinoResource.KEY_SYSTEM_PROPERTY, property);

    return res;
  }

  private static RangerTrinoResource createResource(CatalogSchemaName catalogSchemaName) {
    return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
  }

  private static RangerTrinoResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
    return createResource(catalogSchemaTableName.getCatalogName(),
      catalogSchemaTableName.getSchemaTableName().getSchemaName(),
      catalogSchemaTableName.getSchemaTableName().getTableName());
  }

  private static RangerTrinoResource createResource(String catalogName) {
    return new RangerTrinoResource(catalogName, Optional.empty(), Optional.empty());
  }

  private static RangerTrinoResource createResource(String catalogName, String schemaName) {
    return new RangerTrinoResource(catalogName, Optional.of(schemaName), Optional.empty());
  }

  private static RangerTrinoResource createResource(String catalogName, String schemaName, final String tableName) {
    return new RangerTrinoResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
  }

  private static RangerTrinoResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
    return new RangerTrinoResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
  }

  private static List<RangerTrinoResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
    List<RangerTrinoResource> colRequests = new ArrayList<>();

    if (columns.size() > 0) {
      for (String column : columns) {
        RangerTrinoResource rangerTrinoResource = createResource(table.getCatalogName(),
          table.getSchemaTableName().getSchemaName(),
          table.getSchemaTableName().getTableName(), Optional.of(column));
        colRequests.add(rangerTrinoResource);
      }
    } else {
      colRequests.add(createResource(table.getCatalogName(),
        table.getSchemaTableName().getSchemaName(),
        table.getSchemaTableName().getTableName(), Optional.empty()));
    }
    return colRequests;
  }
}

class RangerTrinoResource
  extends RangerAccessResourceImpl {


  public static final String KEY_CATALOG = "catalog";
  public static final String KEY_SCHEMA = "schema";
  public static final String KEY_TABLE = "table";
  public static final String KEY_COLUMN = "column";
  public static final String KEY_USER = "trinouser";
  public static final String KEY_FUNCTION = "function";
  public static final String KEY_PROCEDURE = "procedure";
  public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
  public static final String KEY_SESSION_PROPERTY = "sessionproperty";

  public RangerTrinoResource() {
  }

  public RangerTrinoResource(String catalogName, Optional<String> schema, Optional<String> table) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
  }

  public RangerTrinoResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
    if (column.isPresent()) {
      setValue(KEY_COLUMN, column.get());
    }
  }

  public String getCatalogName() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getTable() {
    return (String) getValue(KEY_TABLE);
  }

  public String getCatalog() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getSchema() {
    return (String) getValue(KEY_SCHEMA);
  }

  public Optional<SchemaTableName> getSchemaTable() {
    final String schema = getSchema();
    if (StringUtils.isNotEmpty(schema)) {
      return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
    }
    return Optional.empty();
  }
}

class RangerTrinoAccessRequest
  extends RangerAccessRequestImpl {
  public RangerTrinoAccessRequest(RangerTrinoResource resource,
                                   String user,
                                   Set<String> userGroups,
                                   TrinoAccessType trinoAccessType) {
    super(resource, trinoAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);
    setAccessTime(new Date());
  }
}

enum TrinoAccessType {
  CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, GRANT, REVOKE, SHOW, IMPERSONATE, EXECUTE;
}
