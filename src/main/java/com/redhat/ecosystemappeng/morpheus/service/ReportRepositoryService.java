package com.redhat.ecosystemappeng.morpheus.service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.Objects;

import com.mongodb.client.MongoCursor;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Accumulators;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.UpdateOneModel;
import com.mongodb.client.model.Updates;
import com.redhat.ecosystemappeng.morpheus.model.Justification;
import com.redhat.ecosystemappeng.morpheus.model.PaginatedResult;
import com.redhat.ecosystemappeng.morpheus.model.Pagination;
import com.redhat.ecosystemappeng.morpheus.model.Report;
import com.redhat.ecosystemappeng.morpheus.model.ReportError;
import com.redhat.ecosystemappeng.morpheus.model.SortField;
import com.redhat.ecosystemappeng.morpheus.model.SortType;
import com.redhat.ecosystemappeng.morpheus.model.VulnResult;
import com.redhat.ecosystemappeng.morpheus.model.ProductReportsSummary;
import com.redhat.ecosystemappeng.morpheus.model.GroupedReportRow;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@RegisterForReflection(targets = { Document.class })
public class ReportRepositoryService {

  private static final Logger LOGGER = Logger.getLogger(ReportRepositoryService.class);

  private static final String SENT_AT = "sent_at";
  private static final String SUBMITTED_AT = "submitted_at";
  private static final String PRODUCT_ID = "product_id";
  private static final Collection<String> METADATA_DATES = List.of(SUBMITTED_AT, SENT_AT);
  private static final String COLLECTION = "reports";
  private static final Map<String, Bson> STATUS_FILTERS = Map.of(
      "completed", Filters.ne("input.scan.completed_at", null),
      "sent",
      Filters.and(Filters.ne("metadata." + SENT_AT, null), Filters.eq("error", null),
          Filters.eq("input.scan.completed_at", null)),
      "failed", Filters.ne("error", null),
      "queued", Filters.and(Filters.ne("metadata." + SUBMITTED_AT, null), Filters.eq("metadata." + SENT_AT, null),
          Filters.eq("error", null), Filters.eq("input.scan.completed_at", null)),
      "expired", Filters.and(Filters.ne("error", null),Filters.eq("error.type", "expired")),
      "pending", Filters.and(
        Filters.eq("metadata." + SENT_AT, null),
        Filters.eq("metadata." + SUBMITTED_AT, null),
        Filters.ne("metadata." + PRODUCT_ID, null)));

  @Inject
  MongoClient mongoClient;

  @ConfigProperty(name = "quarkus.mongodb.database")
  String dbName;

  @Inject
  ObjectMapper objectMapper;

  @Inject
  ProductRepositoryService productRepositoryService;

  public MongoCollection<Document> getCollection() {
    return mongoClient.getDatabase(dbName).getCollection(COLLECTION);
  }

  private Map<String, String> extractMetadata(Document doc) {
    var metadata = new HashMap<String, String>();
    var metadataField = doc.get("metadata", Document.class);
    if (metadataField != null) {
      metadataField.keySet().forEach(key -> {
        if (METADATA_DATES.contains(key)) {
          Date date = metadataField.getDate(key);
          metadata.put(key, date.toInstant().toString());
        } else {
          metadata.put(key, metadataField.getString(key));
        }
      });
    }
    return metadata;
  }

  public Report toReport(Document doc) {
    if (Objects.isNull(doc)) {
      return null;
    }
    var input = doc.get("input", Document.class);
    var scan = input.get("scan", Document.class);
    var image = input.get("image", Document.class);
    var output = doc.getList("output", Document.class);
    var metadata = extractMetadata(doc);
    var vulnIds = new HashSet<VulnResult>();
    if (Objects.nonNull(output)) {
      output.forEach(o -> {
        var vulnId = o.getString("vuln_id");
        var justification = o.get("justification", Document.class);

        vulnIds.add(new VulnResult(vulnId,
            new Justification(justification.getString("status"), justification.getString("label"))));
      });
    } else {
      scan.getList("vulns", Document.class).forEach(v -> {
        var vulnId = v.getString("vuln_id");
        vulnIds.add(new VulnResult(vulnId, null));
      });
    }

    var id = doc.get(RepositoryConstants.ID_KEY, ObjectId.class).toHexString();

    // Extract git_repo and ref from source_info with type "code" if available
    String gitRepo = null;
    String ref = null;
    var sourceInfo = image.getList("source_info", Document.class);
    if (Objects.nonNull(sourceInfo) && !sourceInfo.isEmpty()) {
      var codeSourceInfo = sourceInfo.stream()
          .filter(si -> "code".equals(si.getString("type")))
          .findFirst()
          .orElse(null);
      if (Objects.nonNull(codeSourceInfo)) {
        gitRepo = codeSourceInfo.getString("git_repo");
        ref = codeSourceInfo.getString("ref");
      }
    }

    // Extract error information if present
    ReportError error = null;
    if (doc.containsKey("error")) {
      var errorDoc = doc.get("error", Document.class);
      if (Objects.nonNull(errorDoc)) {
        error = new ReportError(
            errorDoc.getString("type"),
            errorDoc.getString("message"));
      }
    }

    return new Report(id, scan.getString(RepositoryConstants.ID_SORT),
        scan.getString("started_at"),
        scan.getString("completed_at"),
        image.getString("name"),
        image.getString("tag"),
        getStatus(doc, metadata),
        vulnIds,
        metadata,
        gitRepo,
        ref,
        error);
  }

  private String getStatus(Document doc, Map<String, String> metadata) {
    if (doc.containsKey("error")) {
      var error = doc.get("error", Document.class);
      if (error.getString("type").equals("expired")) {
        return "expired";
      }
      return "failed";
    }
    var input = doc.get("input", Document.class);
    if (Objects.nonNull(input)) {
      var scan = input.get("scan", Document.class);
      if (Objects.nonNull(scan.getString("completed_at"))) {
        return "completed";
      }
    }
    if (Objects.nonNull(metadata)) {
      if (Objects.nonNull(metadata.get(SENT_AT))) {
        return "sent";
      }
      if (Objects.nonNull(metadata.get(SUBMITTED_AT))) {
        return "queued";
      }
      if (Objects.nonNull(metadata.get(PRODUCT_ID))) {
        return "pending";
      }
    }

    return "unknown";
  }

  public void updateWithOutput(List<String> ids, JsonNode report)
      throws JsonMappingException, JsonProcessingException {
    
    Set<String> productIds = getProductId(ids);
    
    List<Document> outputDocs = objectMapper.readValue(report.get("output").toPrettyString(),
        new TypeReference<List<Document>>() {

        });
    var scan = report.get("input").get("scan").toPrettyString();
    var info = report.get("info").toPrettyString();
    var updates = Updates.combine(Updates.set("input.scan", Document.parse(scan)),
        Updates.set("info", Document.parse(info)),
        Updates.set("output", outputDocs),
        Updates.unset("error"));
    var bulk = ids.stream()
        .map(id -> new UpdateOneModel<Document>(Filters.eq(RepositoryConstants.ID_KEY, new ObjectId(id)), updates))
        .toList();
    getCollection().bulkWrite(bulk);
    
    productIds.forEach(this::checkAndStoreProductCompletion);
  }

  public void updateWithError(String id, String errorType, String errorMessage) {
    String productId = getProductId(id);  
    
    var error = new Document("type", errorType).append("message", errorMessage);
    getCollection().updateOne(new Document(RepositoryConstants.ID_KEY, new ObjectId(id)), Updates.set("error", error));
    
    if (productId != null) {
      checkAndStoreProductCompletion(productId);
    }
  }

  public Report save(String data) {
    var doc = Document.parse(data);
    var inserted = getCollection().insertOne(doc);
    return get(inserted.getInsertedId().asObjectId().getValue());
  }

  public void setAsSent(String id) {
    var objId = new ObjectId(id);
    getCollection().updateOne(Filters.eq(RepositoryConstants.ID_KEY, objId),
        Updates.set("metadata." + SENT_AT, Instant.now()));
  }

  public void setAsSubmitted(String id, String byUser) {
    var objId = new ObjectId(id);

    List<Bson> updates = new ArrayList<>();
    updates.add(Updates.set("metadata." + SUBMITTED_AT, Instant.now()));
    updates.add(Updates.set("metadata.user", byUser));

    getCollection().updateOne(Filters.eq(RepositoryConstants.ID_KEY, objId), updates);
  }

  public void setAsRetried(String id, String byUser) {
    var objId = new ObjectId(id);
    getCollection().updateOne(Filters.eq(RepositoryConstants.ID_KEY, objId),
        Updates.combine(
            Updates.set("metadata." + SUBMITTED_AT, Instant.now()),
            Updates.set("metadata.user", byUser),
            Updates.unset("error")));
  }

  public void updateReportInput(String id, JsonNode input) throws JsonProcessingException {
    var objId = new ObjectId(id);
    var inputDoc = Document.parse(input.toPrettyString());
    getCollection().updateOne(Filters.eq(RepositoryConstants.ID_KEY, objId),
        Updates.set("input", inputDoc));
    LOGGER.debugf("Updated input for report %s", id);
  }

  public void saveFullReport(String id, JsonNode report) throws JsonProcessingException {
    var objId = new ObjectId(id);
    var reportDoc = Document.parse(objectMapper.writeValueAsString(report));
    // Preserve the _id field
    reportDoc.put(RepositoryConstants.ID_KEY, objId);
    getCollection().replaceOne(Filters.eq(RepositoryConstants.ID_KEY, objId), reportDoc);
    LOGGER.debugf("Saved full report document %s to MongoDB", id);
  }

  private Report get(ObjectId id) {
    var doc = getCollection().find(Filters.eq(RepositoryConstants.ID_KEY, id)).first();
    return toReport(doc);
  }

  public String findById(String id) {
    var result = getCollection().find(Filters.eq(RepositoryConstants.ID_KEY, new ObjectId(id))).first();
    if (result == null) {
      return null;
    }
    return result.toJson();
  }

  public List<Report> findByName(String name) {
    var results = new ArrayList<Report>();
    getCollection().find(Filters.eq("input.scan.id", name)).cursor().forEachRemaining(d -> results.add(toReport(d)));
    return results;
  }

  private static final Map<String, String> SORT_MAPPINGS = Map.of(
      "completedAt", "input.scan.completed_at",
      "submittedAt", "metadata.submitted_at",
      "vuln_id", "output.vuln_id",
      "ref", "input.image.source_info.ref",
      "gitRepo", "input.image.source_info.git_repo");

  public PaginatedResult<Report> list(Map<String, String> queryFilter, List<SortField> sortFields,
      Pagination pagination) {
    List<Report> reports = new ArrayList<>();
    var filter = buildQueryFilter(queryFilter);

    List<Bson> sorts = new ArrayList<>();
    sortFields.forEach(sf -> {
      if ("state".equals(sf.field())) {
        sorts.add(Sorts.descending("input.scan.completed_at"));
        sorts.add(Sorts.ascending("error.type"));
      } else {
        var fieldName = SORT_MAPPINGS.get(sf.field());
        if (fieldName != null) {
          if (SortType.ASC.equals(sf.type())) {
            sorts.add(Sorts.ascending(fieldName));
          } else {
            sorts.add(Sorts.descending(fieldName));
          }
        }
      }
    });
    
    var totalElements = getCollection().countDocuments(filter);
    int totalPages = (int) Math.ceil((double) totalElements / pagination.size());

    getCollection().find(filter)
        .skip(pagination.page() * pagination.size())
        .sort(Sorts.orderBy(sorts))
        .limit(pagination.size())
        .cursor()
        .forEachRemaining(d -> reports.add(toReport(d)));
    return new PaginatedResult<Report>(totalElements, totalPages, reports.stream());
  }


  public List<String> getProductIds() {
    List<String> productIds = new ArrayList<>();
    Bson filter = Filters.exists("metadata.product_id", true);
    getCollection()
      .distinct("metadata.product_id", filter, String.class)
      .iterator()
      .forEachRemaining(pid -> {
        if (pid != null && !pid.isEmpty()) {
          productIds.add(pid);
        }
      });
    return productIds;
  }

  public ProductReportsSummary getProductSummaryData(String productId) {
    Bson productFilter = Filters.eq("metadata.product_id", productId);
    Map<String, Set<Justification>> cveSet = new HashMap<>();
    Map<String, Integer> componentStates = new HashMap<>();
    Map<String, Map<String, Integer>> cveStatusCounts = new HashMap<>();
    String productState = "unknown";

    getCollection()
      .find(productFilter)
      .iterator()
      .forEachRemaining(doc -> {
        Map<String, String> metadata = extractMetadata(doc);
        String reportStatus = getStatus(doc, metadata);
        componentStates.merge(reportStatus, 1, Integer::sum);

        Object inputObj = doc.get("input");
        if (inputObj instanceof org.bson.Document inputDoc) {
          Object scanObj = inputDoc.get("scan");
          if (scanObj instanceof org.bson.Document scanDoc) {
            Object vulnsObj = scanDoc.get("vulns");
            if (vulnsObj instanceof List<?> vulnsList) {
              for (Object vulnObj : vulnsList) {
                if (vulnObj instanceof org.bson.Document vulnDoc) {
                  String cve = vulnDoc.getString("vuln_id");
                  if (cve != null && !cve.isEmpty()) {
                    cveSet.putIfAbsent(cve, new HashSet<>());
                  }
                }
              }
            }
          }
        }

        Object outputObj = doc.get("output");
        if (outputObj instanceof List<?> outputList) {
          for (Object output : outputList) {
            if (output instanceof org.bson.Document outputDoc) {
              String cve = outputDoc.getString("vuln_id");
              if (cve != null && !cve.isEmpty()) {
                Set<Justification> justifications = cveSet.computeIfAbsent(cve, k -> new HashSet<>());
                Object justificationObj = outputDoc.get("justification");
                if (justificationObj instanceof org.bson.Document justificationDoc) {
                  String status = justificationDoc.getString("status");
                  String label = justificationDoc.getString("label");
                  if (status != null && !status.isEmpty() && label != null && !label.isEmpty()) {
                    justifications.add(new Justification(status, label));
                    cveStatusCounts.computeIfAbsent(cve, k -> new HashMap<>()).merge(status, 1, Integer::sum);
                  }
                }
              }
            }
          }
        }
      });

    if (componentStates.containsKey("pending") || componentStates.containsKey("queued") || componentStates.containsKey("sent")) {
      productState = "analysing";
    } else {
      productState = "completed";
    }

    return new ProductReportsSummary(
      productState,
      componentStates,
      cveSet,
      cveStatusCounts
    );
  }

  private String getProductId(String reportId) {
    Document doc = getCollection().find(Filters.eq(RepositoryConstants.ID_KEY, new ObjectId(reportId))).first();
    if (Objects.nonNull(doc)) {
      var metadata = doc.get("metadata", Document.class);
      if (Objects.nonNull(metadata)) {
        return metadata.getString("product_id");
      }
    }
    return null;
  }

  private Set<String> getProductId(Collection<String> reportIds) {
    Set<String> productIds = new HashSet<>();
    reportIds.forEach(id -> {
      String productId = getProductId(id);
      if (Objects.nonNull(productId)) {
        productIds.add(productId);
      }
    });
    return productIds;
  }

  private void checkAndStoreProductCompletion(String productId) {
    // Check if this product just became completed
    Bson productFilter = Filters.eq("metadata.product_id", productId);
    boolean hasCompletionTimeStored = false;
    boolean hasPendingReports = false;
    String latestCompletionTime = null;

    try (var cursor = getCollection().find(productFilter).cursor()) {
      while (cursor.hasNext()) {
        Document doc = cursor.next();
        Map<String, String> metadata = extractMetadata(doc);
        
        if (Objects.nonNull(metadata.get("product_completed_at"))) {
          hasCompletionTimeStored = true;
          break;
        }
        
        String reportStatus = getStatus(doc, metadata);
        
        if ("pending".equals(reportStatus) || "queued".equals(reportStatus) || "sent".equals(reportStatus)) {
          hasPendingReports = true;
          break;
        }
        
        if ("completed".equals(reportStatus) || "failed".equals(reportStatus) || "expired".equals(reportStatus)) {
          String completedAt = getReportCompletionTime(doc);
          if (Objects.nonNull(completedAt) && (Objects.isNull(latestCompletionTime) || completedAt.compareTo(latestCompletionTime) > 0)) {
            latestCompletionTime = completedAt;
          }
        }
      }
    }

    if (!hasCompletionTimeStored && !hasPendingReports && Objects.nonNull(latestCompletionTime)) {
      productRepositoryService.updateCompletedAt(productId, latestCompletionTime);
      LOGGER.infof("Product %s completed at %s", productId, latestCompletionTime);
    }
  }

  private String getReportCompletionTime(Document doc) {
    var input = doc.get("input", Document.class);
    if (Objects.nonNull(input)) {
      var scan = input.get("scan", Document.class);
      if (Objects.nonNull(scan)) {
        String completedAt = scan.getString("completed_at");
        if (Objects.nonNull(completedAt)) {
          return completedAt;
        }
      }
    }
    
    var metadata = extractMetadata(doc);
    String submittedAt = metadata.get("submitted_at");
    return submittedAt;
  }

  public List<String> getReportIdsByProduct(List<String> productIds) {
    List<String> reportIds = new ArrayList<>();
    if (Objects.isNull(productIds) || productIds.isEmpty()) {
      return reportIds;
    }
    Bson filter = Filters.in("metadata.product_id", productIds);
    getCollection()
      .find(filter)
      .iterator()
      .forEachRemaining(doc -> {
        ObjectId id = doc.getObjectId(RepositoryConstants.ID_KEY);
        if (Objects.nonNull(id)) {
          reportIds.add(id.toHexString());
        }
      });
    return reportIds;
  }

  public boolean remove(String id) {
    String productId = getProductId(id);
    
    boolean result = getCollection().deleteOne(Filters.eq(RepositoryConstants.ID_KEY, new ObjectId(id))).wasAcknowledged();
    
    if (result && Objects.nonNull(productId)) {
      checkAndStoreProductCompletion(productId);
    }
    
    return result;
  }

  public boolean remove(Collection<String> ids) {
    Set<String> productIds = getProductId(ids);
    
    boolean result = getCollection()
        .deleteMany(Filters.in(RepositoryConstants.ID_KEY, ids.stream()
            .map(id -> new ObjectId(id)).toList()))
        .wasAcknowledged();
    
    if (result) {
      productIds.forEach(this::checkAndStoreProductCompletion);
    }
    
    return result;
  }

  public Collection<String> remove(Map<String, String> queryFilter) {

    var filter = buildQueryFilter(queryFilter);
    Collection collection = new ArrayList();
    MongoCursor<Document> docs = getCollection().find(filter).cursor();
      for (MongoCursor<Document> it = docs; it.hasNext(); ) {
        Document doc = it.next();
        String docInternalId = doc.get(RepositoryConstants.ID_KEY, ObjectId.class).toHexString();
        collection.add(docInternalId);


      }
    getCollection().deleteMany(filter).wasAcknowledged();
    return collection;
  }

  public void removeBefore(Instant threshold) {
    var count = getCollection().deleteMany(Filters.lt("metadata." + SUBMITTED_AT, threshold)).getDeletedCount();
    LOGGER.debugf("Removed %s reports before %s", count, threshold);
  }

  private void handleMultipleValues(String valueString, 
                                     java.util.function.Function<String, Bson> filterBuilder,
                                     List<Bson> filters) {
    String[] values = valueString.split(",");
    if (values.length == 1) {
      filters.add(filterBuilder.apply(values[0].trim()));
    } else {
      List<Bson> valueFilters = new ArrayList<>();
      for (String value : values) {
        valueFilters.add(filterBuilder.apply(value.trim()));
      }
      filters.add(valueFilters.size() == 1 ? valueFilters.get(0) : Filters.or(valueFilters));
    }
  }

  private Bson buildQueryFilter(Map<String, String> queryFilter) {
    List<Bson> filters = new ArrayList<>();
    String vulnId = queryFilter.get("vulnId");
    String exploitIqStatus = queryFilter.get("exploitIqStatus");
    
    queryFilter.entrySet().forEach(e -> {

      switch (e.getKey()) {
        case "reportId":
          handleMultipleValues(e.getValue(), (value) -> 
            Filters.eq("input.scan.id", value), filters);
          break;
        case "vulnId":
          handleMultipleValues(e.getValue(), (value) -> 
            Filters.elemMatch("input.scan.vulns", Filters.eq("vuln_id", value)), filters);
          break;
        case "status":
          var statusValues = e.getValue().split(",");
          if (statusValues.length == 1) {
            var statusFilter = STATUS_FILTERS.get(statusValues[0].trim());
            if (statusFilter != null) {
              filters.add(statusFilter);
            }
          } else {
            List<Bson> statusFilters = new ArrayList<>();
            for (String statusValue : statusValues) {
              var statusFilter = STATUS_FILTERS.get(statusValue.trim());
              if (statusFilter != null) {
                statusFilters.add(statusFilter);
              }
            }
            if (!statusFilters.isEmpty()) {
              filters.add(Filters.or(statusFilters));
            }
          }
          break;
        case "imageName":
          handleMultipleValues(e.getValue(), (value) -> 
            Filters.eq("input.image.name", value), filters);
          break;
        case "imageTag":
          handleMultipleValues(e.getValue(), (value) -> 
            Filters.eq("input.image.tag", value), filters);
          break;
        case "productId":
          handleMultipleValues(e.getValue(), (value) -> 
            Filters.eq("metadata.product_id", value), filters);
          break;
        case "gitRepo":
          var gitRepoValues = e.getValue().split(",");
          if (gitRepoValues.length == 1) {
            filters.add(Filters.elemMatch("input.image.source_info", 
              Filters.and(
                Filters.eq("type", "code"),
                Filters.regex("git_repo", gitRepoValues[0].trim(), "i")
              )
            ));
          } else {
            List<Bson> gitRepoFilters = new ArrayList<>();
            for (String gitRepoValue : gitRepoValues) {
              gitRepoFilters.add(Filters.elemMatch("input.image.source_info", 
                Filters.and(
                  Filters.eq("type", "code"),
                  Filters.regex("git_repo", gitRepoValue.trim(), "i")
                )
              ));
            }
            filters.add(Filters.or(gitRepoFilters));
          }
          break;
        case "exploitIqStatus":
          break;
        default:
          handleMultipleValues(e.getValue(), (value) -> 
            Filters.eq(String.format("metadata.%s", e.getKey()), value), filters);
          break;

      }
    });
    
    if (exploitIqStatus != null && !exploitIqStatus.isEmpty()) {
      String[] exploitIqStatusValues = exploitIqStatus.split(",");
      List<Bson> exploitIqStatusFilters = new ArrayList<>();
      
      for (String statusValue : exploitIqStatusValues) {
        String trimmedStatus = statusValue.trim();
        if (vulnId != null && !vulnId.isEmpty()) {
          exploitIqStatusFilters.add(Filters.elemMatch("output", 
            Filters.and(
              Filters.eq("vuln_id", vulnId),
              Filters.eq("justification.status", trimmedStatus)
            )
          ));
        } else {
          exploitIqStatusFilters.add(Filters.elemMatch("output", 
            Filters.eq("justification.status", trimmedStatus)
          ));
        }
      }
      
      if (!exploitIqStatusFilters.isEmpty()) {
        filters.add(exploitIqStatusFilters.size() == 1 
          ? exploitIqStatusFilters.get(0) 
          : Filters.or(exploitIqStatusFilters));
      }
    }
    var filter = Filters.empty();
    if (!filters.isEmpty()) {
      filter = Filters.and(filters);
    }
    return filter;
  }

  /**
   * Count reports with at least one vulnerable CVE (justification.status = "TRUE")
   */
  public long countVulnerableReports() {
    // Reports with at least one output justification status = "TRUE"
    Bson filter = Filters.elemMatch("output", Filters.eq("justification.status", "TRUE"));
    return getCollection().countDocuments(filter);
  }

  /**
   * Count reports with only non-vulnerable CVEs (all justifications are "FALSE" or no vulns)
   * This includes reports with no vulnerabilities
   */
  public long countNonVulnerableReports() {
    // Reports that are completed (have output) but don't have any "TRUE" justifications
    Bson hasOutput = Filters.and(
        Filters.ne("output", null),
        Filters.exists("output", true)
    );
    Bson noVulnerable = Filters.not(Filters.elemMatch("output", Filters.eq("justification.status", "TRUE")));
    Bson filter = Filters.and(hasOutput, noVulnerable);
    return getCollection().countDocuments(filter);
  }

  /**
   * Count pending requests (state = "pending")
   */
  public long countPendingRequests() {
    Bson filter = STATUS_FILTERS.get("pending");
    return getCollection().countDocuments(filter);
  }

  /**
   * Count new reports submitted today (using server timezone, calendar day 00:00:00 to 23:59:59)
   */
  public long countNewReportsToday() {
    java.time.ZonedDateTime now = java.time.ZonedDateTime.now();
    java.time.ZonedDateTime startOfDay = now.toLocalDate().atStartOfDay(now.getZone());
    java.time.ZonedDateTime endOfDay = startOfDay.plusDays(1).minusSeconds(1);
    
    Instant startInstant = startOfDay.toInstant();
    Instant endInstant = endOfDay.toInstant();
    
    Bson filter = Filters.and(
        Filters.gte("metadata." + SUBMITTED_AT, startInstant),
        Filters.lte("metadata." + SUBMITTED_AT, endInstant)
    );
    return getCollection().countDocuments(filter);
  }

  public PaginatedResult<GroupedReportRow> listGrouped(
      Map<String, String> queryFilter,
      List<SortField> sortFields,
      Pagination pagination) {
    Bson baseFilter = buildQueryFilter(queryFilter);
    List<GroupedReportRow> result = new ArrayList<>();

    // Pipeline 1: Reports WITH product_id - Group by (productId, cveId)
    List<Bson> withProductIdPipeline = new ArrayList<>();

    // Match filter
    withProductIdPipeline.add(Aggregates.match(
        Filters.and(
            Filters.exists("metadata.product_id", true),
            baseFilter)));

    // Unwind CVEs to get one document per CVE
    withProductIdPipeline.add(Aggregates.unwind("$input.scan.vulns"));

    // Unwind output to get justification.status for each CVE
    // First, ensure output exists and is an array, then filter to match CVE
    withProductIdPipeline.add(new Document("$addFields",
        new Document("outputArray",
            new Document("$ifNull", Arrays.asList("$output", new ArrayList<>())))));
    withProductIdPipeline.add(new Document("$addFields",
        new Document("matchedOutput",
            new Document("$filter", new Document("input", "$outputArray")
                .append("as", "out")
                .append("cond", new Document("$eq", Arrays.asList(
                    "$$out.vuln_id",
                    "$input.scan.vulns.vuln_id")))))));
    withProductIdPipeline.add(new Document("$unwind",
        new Document("path", "$matchedOutput")
            .append("preserveNullAndEmptyArrays", true)));

    // Group by (productId, cveId) and aggregate
    // Collect all statuses for aggregation, and get report IDs
    withProductIdPipeline.add(Aggregates.group(
        new Document("productId", "$metadata.product_id")
            .append("cveId", "$input.scan.vulns.vuln_id"),
        Accumulators.sum("total", 1),
        Accumulators.sum("completed",
            new Document("$cond", Arrays.asList(
                new Document("$ne", Arrays.asList("$input.scan.completed_at", null)),
                1, 0))),
        Accumulators.min("earliestSubmittedAt", "$metadata.submitted_at"),
        Accumulators.min("earliestCompletedAt", "$input.scan.completed_at"),
        Accumulators.first("firstReportId", "$input.scan.id"),
        Accumulators.first("firstMongoId", "$_id"),
        Accumulators.push("statuses",
            new Document("$ifNull", Arrays.asList(
                "$matchedOutput.justification.status",
                null)))));

    // Add sorting
    if (sortFields != null && !sortFields.isEmpty()) {
      List<Bson> sorts = new ArrayList<>();
      sortFields.forEach(sf -> {
        String field = sf.field();
        SortType direction = sf.type();

        if ("submittedAt".equals(field)) {
          if (direction == SortType.ASC) {
            sorts.add(Sorts.ascending("earliestSubmittedAt"));
          } else {
            sorts.add(Sorts.descending("earliestSubmittedAt"));
          }
        } else if ("productId".equals(field)) {
          if (direction == SortType.ASC) {
            sorts.add(Sorts.ascending("_id.productId"));
          } else {
            sorts.add(Sorts.descending("_id.productId"));
          }
        } else if ("cveId".equals(field)) {
          if (direction == SortType.ASC) {
            sorts.add(Sorts.ascending("_id.cveId"));
          } else {
            sorts.add(Sorts.descending("_id.cveId"));
          }
        }
      });
      if (!sorts.isEmpty()) {
        withProductIdPipeline.add(Aggregates.sort(Sorts.orderBy(sorts)));
      }
    }

    // Count total groups (for pagination)
    Document countDoc = getCollection()
        .aggregate(createCountPipeline(baseFilter, true), Document.class)
        .first();
    long totalWithProductId = (countDoc != null) ? countDoc.getInteger("count", 0) : 0;

    // Add pagination
    withProductIdPipeline.add(Aggregates.skip(pagination.page() * pagination.size()));
    withProductIdPipeline.add(Aggregates.limit(pagination.size()));

    // Project to final format
    withProductIdPipeline.add(Aggregates.project(Projections.fields(
        Projections.computed("reportId", "$_id.productId"),
        Projections.computed("reportType", "product"),
        Projections.computed("cveId", "$_id.cveId"),
        Projections.computed("repositoriesAnalyzed",
            new Document("$concat", Arrays.asList(
                new Document("$toString", "$completed"),
                "/",
                new Document("$toString", "$total"),
                " analyzed"))),
        Projections.computed("statuses", "$statuses"),
        Projections.computed("completedAt", "$earliestCompletedAt"),
        Projections.computed("mongoId",
            new Document("$toString", "$firstMongoId")),
        Projections.excludeId())));

    // Execute pipeline 1 and process cveStatusCounts
    getCollection().aggregate(withProductIdPipeline, Document.class)
        .forEach(doc -> {
          String cveId = doc.getString("cveId");
          List<?> statuses = doc.getList("statuses", Object.class);
          
          // Build cveStatusCounts map (direct status -> count, since each row is for one CVE)
          Map<String, Integer> cveStatusCounts = new HashMap<>();
          
          if (statuses != null) {
            for (Object statusObj : statuses) {
              if (statusObj != null) {
                String status = statusObj.toString();
                cveStatusCounts.merge(status, 1, Integer::sum);
              }
            }
          }
          
          String completedAt = doc.getString("completedAt");
          String mongoId = doc.getString("mongoId");
          
          result.add(new GroupedReportRow(
              doc.getString("reportId"),
              doc.getString("reportType"),
              cveId,
              doc.getString("repositoriesAnalyzed"),
              cveStatusCounts,
              completedAt != null ? completedAt : "",
              mongoId != null ? mongoId : ""));
        });

    // Pipeline 2: Reports WITHOUT product_id - Individual rows
    List<Bson> withoutProductIdPipeline = new ArrayList<>();

    // Match filter
    withoutProductIdPipeline.add(Aggregates.match(
        Filters.and(
            Filters.or(
                Filters.exists("metadata.product_id", false),
                Filters.eq("metadata.product_id", null)),
            baseFilter)));

    // Project to normalize CVE array (handle null/empty CVEs)
    // Create a field that ensures we always have at least one CVE to unwind
    Document cveArrayExpr = new Document("$cond", Arrays.asList(
        new Document("$and", Arrays.asList(
            new Document("$ne", Arrays.asList("$input.scan.vulns", null)),
            new Document("$gt", Arrays.asList(
                new Document("$size", 
                    new Document("$ifNull", Arrays.asList("$input.scan.vulns", new ArrayList<>()))),
                0)))),
        "$input.scan.vulns",
        Arrays.asList(new Document("vuln_id", "-"))));
    
    withoutProductIdPipeline.add(Aggregates.project(Projections.fields(
        Projections.include("metadata", "input", "error"),
        Projections.computed("cveToUnwind", cveArrayExpr))));
    
    // Unwind CVEs
    withoutProductIdPipeline.add(Aggregates.unwind("$cveToUnwind"));

    // Add sorting
    if (sortFields != null && !sortFields.isEmpty()) {
      List<Bson> sorts = new ArrayList<>();
      sortFields.forEach(sf -> {
        String field = sf.field();
        SortType direction = sf.type();

        if ("submittedAt".equals(field)) {
          if (direction == SortType.ASC) {
            sorts.add(Sorts.ascending("metadata.submitted_at"));
          } else {
            sorts.add(Sorts.descending("metadata.submitted_at"));
          }
        } else if ("name".equals(field)) {
          if (direction == SortType.ASC) {
            sorts.add(Sorts.ascending("input.image.name"));
          } else {
            sorts.add(Sorts.descending("input.image.name"));
          }
        } else if ("cveId".equals(field)) {
          if (direction == SortType.ASC) {
            sorts.add(Sorts.ascending("cveToUnwind.vuln_id"));
          } else {
            sorts.add(Sorts.descending("cveToUnwind.vuln_id"));
          }
        }
      });
      if (!sorts.isEmpty()) {
        withoutProductIdPipeline.add(Aggregates.sort(Sorts.orderBy(sorts)));
      }
    }

    // Count total
    Document countDocWithout = getCollection()
        .aggregate(createCountPipeline(baseFilter, false), Document.class)
        .first();
    long totalWithoutProductId = (countDocWithout != null) ? countDocWithout.getInteger("count", 0) : 0;

    // Add pagination
    withoutProductIdPipeline.add(Aggregates.skip(pagination.page() * pagination.size()));
    withoutProductIdPipeline.add(Aggregates.limit(pagination.size()));

    // Unwind output to get justification.status for the CVE
    withoutProductIdPipeline.add(new Document("$addFields",
        new Document("outputArray",
            new Document("$ifNull", Arrays.asList("$output", new ArrayList<>())))));
    withoutProductIdPipeline.add(new Document("$addFields",
        new Document("matchedOutput",
            new Document("$filter", new Document("input", "$outputArray")
                .append("as", "out")
                .append("cond", new Document("$eq", Arrays.asList(
                    "$$out.vuln_id",
                    "$cveToUnwind.vuln_id")))))));
    withoutProductIdPipeline.add(new Document("$addFields",
        new Document("firstMatchedOutput",
            new Document("$arrayElemAt", Arrays.asList("$matchedOutput", 0)))));

    // Project to final format
    withoutProductIdPipeline.add(Aggregates.project(Projections.fields(
        Projections.computed("reportId", "$input.scan.id"),
        Projections.computed("reportType", "component"),
        Projections.computed("cveId",
            new Document("$ifNull", Arrays.asList(
                "$cveToUnwind.vuln_id",
                "-"))),
        Projections.computed("repositoriesAnalyzed", "1"),
        Projections.computed("justificationStatus",
            new Document("$ifNull", Arrays.asList(
                "$firstMatchedOutput.justification.status",
                null))),
        Projections.computed("completedAt", "$input.scan.completed_at"),
        Projections.computed("mongoId",
            new Document("$toString", "$_id")),
        Projections.excludeId())));

    // Execute pipeline 2
    getCollection().aggregate(withoutProductIdPipeline, Document.class)
        .forEach(doc -> {
          String cveId = doc.getString("cveId");
          String justificationStatus = doc.getString("justificationStatus");
          
          // Build cveStatusCounts map for single report (direct status -> count)
          Map<String, Integer> cveStatusCounts = new HashMap<>();
          if (justificationStatus != null && !justificationStatus.isEmpty()) {
            cveStatusCounts.put(justificationStatus, 1);
          }
          
          String completedAt = doc.getString("completedAt");
          String mongoId = doc.getString("mongoId");
          
          result.add(new GroupedReportRow(
              doc.getString("reportId"),
              doc.getString("reportType"),
              cveId,
              doc.getString("repositoriesAnalyzed"),
              cveStatusCounts,
              completedAt != null ? completedAt : "",
              mongoId != null ? mongoId : ""));
        });

    // Calculate totals
    long totalElements = totalWithProductId + totalWithoutProductId;
    int totalPages = (int) Math.ceil((double) totalElements / pagination.size());

    return new PaginatedResult<>(totalElements, totalPages, result.stream());
  }

  // Helper method to create count pipeline
  private List<Bson> createCountPipeline(Bson baseFilter, boolean withProductId) {
    List<Bson> pipeline = new ArrayList<>();

    if (withProductId) {
      pipeline.add(Aggregates.match(
          Filters.and(
              Filters.exists("metadata.product_id", true),
              baseFilter)));
      pipeline.add(Aggregates.unwind("$input.scan.vulns"));
      pipeline.add(Aggregates.group(
          new Document("productId", "$metadata.product_id")
              .append("cveId", "$input.scan.vulns.vuln_id")));
    } else {
      pipeline.add(Aggregates.match(
          Filters.and(
              Filters.or(
                  Filters.exists("metadata.product_id", false),
                  Filters.eq("metadata.product_id", null)),
              baseFilter)));
      pipeline.add(Aggregates.unwind("$input.scan.vulns"));
    }

    // Count groups
    pipeline.add(Aggregates.count("count"));

    return pipeline;
  }
}
