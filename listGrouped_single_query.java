/**
 * Single MongoDB aggregation pipeline for listGrouped
 * Uses $facet to run both product and component pipelines in parallel,
 * then combines, sorts, and paginates the results
 */
public PaginatedResult<GroupedReportRow> listGrouped(
    Map<String, String> queryFilter,
    List<SortField> sortFields,
    Pagination pagination) {
  Bson baseFilter = buildQueryFilter(queryFilter);
  List<GroupedReportRow> result = new ArrayList<>();

  // Build sort expressions for MongoDB
  List<Bson> sortExpressions = new ArrayList<>();
  if (sortFields != null && !sortFields.isEmpty()) {
    sortFields.forEach(sf -> {
      String field = sf.field();
      SortType direction = sf.type();
      
      if ("submittedAt".equals(field)) {
        sortExpressions.add(direction == SortType.ASC 
            ? Sorts.ascending("submittedAt")
            : Sorts.descending("submittedAt"));
      } else if ("productId".equals(field) || "reportId".equals(field) || "name".equals(field)) {
        sortExpressions.add(direction == SortType.ASC
            ? Sorts.ascending("reportId")
            : Sorts.descending("reportId"));
      } else if ("cveId".equals(field)) {
        sortExpressions.add(direction == SortType.ASC
            ? Sorts.ascending("cveId")
            : Sorts.descending("cveId"));
      } else if ("completedAt".equals(field)) {
        sortExpressions.add(direction == SortType.ASC
            ? Sorts.ascending("completedAt")
            : Sorts.descending("completedAt"));
      }
    });
  }
  // Default sort if none specified
  if (sortExpressions.isEmpty()) {
    sortExpressions.add(Sorts.descending("submittedAt"));
  }

  // Single aggregation pipeline using $facet
  List<Bson> pipeline = new ArrayList<>();
  
  // Step 1: Match base filter
  pipeline.add(Aggregates.match(baseFilter));
  
  // Step 2: Add helper field to identify product vs component
  pipeline.add(new Document("$addFields",
      new Document("hasProductId",
          new Document("$and", Arrays.asList(
              new Document("$ne", Arrays.asList("$metadata.product_id", null)),
              new Document("$ne", Arrays.asList("$metadata.product_id", "")))))));

  // Step 3: Use $facet to run both pipelines in parallel
  Document facetStage = new Document("$facet",
      new Document("products", buildProductPipeline())
          .append("components", buildComponentPipeline()));
  pipeline.add(facetStage);

  // Step 4: Combine both arrays
  pipeline.add(new Document("$project",
      new Document("allResults",
          new Document("$concatArrays", Arrays.asList("$products", "$components")))));

  // Step 5: Unwind combined array
  pipeline.add(new Document("$unwind", "$allResults"));

  // Step 6: Replace root with result document
  pipeline.add(new Document("$replaceRoot", new Document("newRoot", "$allResults")));

  // Step 7: Sort combined results
  pipeline.add(Aggregates.sort(Sorts.orderBy(sortExpressions)));

  // Step 8: Count total (separate pipeline for efficiency)
  long totalElements = getTotalCount(baseFilter);

  // Step 9: Apply pagination
  pipeline.add(Aggregates.skip(pagination.page() * pagination.size()));
  pipeline.add(Aggregates.limit(pagination.size()));

  // Step 10: Execute and process results
  getCollection().aggregate(pipeline, Document.class)
      .forEach(doc -> {
        String reportType = doc.getString("reportType");
        String cveId = doc.getString("cveId");
        Map<String, Integer> cveStatusCounts = new HashMap<>();

        if ("product".equals(reportType)) {
          List<?> statuses = doc.getList("statuses", Object.class);
          if (statuses != null) {
            for (Object statusObj : statuses) {
              if (statusObj != null) {
                String status = statusObj.toString();
                cveStatusCounts.merge(status, 1, Integer::sum);
              }
            }
          }
        } else {
          String justificationStatus = doc.getString("justificationStatus");
          if (justificationStatus != null && !justificationStatus.isEmpty()) {
            cveStatusCounts.put(justificationStatus, 1);
          }
        }

        result.add(new GroupedReportRow(
            doc.getString("reportId"),
            reportType,
            cveId,
            doc.getString("repositoriesAnalyzed"),
            cveStatusCounts,
            doc.getString("completedAt") != null ? doc.getString("completedAt") : "",
            doc.getString("mongoId") != null ? doc.getString("mongoId") : ""));
      });

  int totalPages = (int) Math.ceil((double) totalElements / pagination.size());
  return new PaginatedResult<>(totalElements, totalPages, result.stream());
}

/**
 * Build the product pipeline (for $facet)
 */
private List<Document> buildProductPipeline() {
  return Arrays.asList(
      new Document("$match", new Document("hasProductId", true)),
      new Document("$unwind", "$input.scan.vulns"),
      new Document("$addFields",
          new Document("outputArray",
              new Document("$ifNull", Arrays.asList("$output", new ArrayList<>())))),
      new Document("$addFields",
          new Document("matchedOutput",
              new Document("$filter", new Document("input", "$outputArray")
                  .append("as", "out")
                  .append("cond", new Document("$eq", Arrays.asList(
                      "$$out.vuln_id",
                      "$input.scan.vulns.vuln_id")))))),
      new Document("$unwind",
          new Document("path", "$matchedOutput")
              .append("preserveNullAndEmptyArrays", true)),
      new Document("$group",
          new Document("_id",
              new Document("productId", "$metadata.product_id")
                  .append("cveId", "$input.scan.vulns.vuln_id"))
              .append("total", new Document("$sum", 1))
              .append("completed", new Document("$sum",
                  new Document("$cond", Arrays.asList(
                      new Document("$ne", Arrays.asList("$input.scan.completed_at", null)),
                      1, 0))))
              .append("earliestSubmittedAt", new Document("$min", "$metadata.submitted_at"))
              .append("earliestCompletedAt", new Document("$min", "$input.scan.completed_at"))
              .append("firstMongoId", new Document("$first", "$_id"))
              .append("statuses", new Document("$push",
                  new Document("$ifNull", Arrays.asList(
                      "$matchedOutput.justification.status",
                      null))))),
      new Document("$project",
          new Document("reportId", "$_id.productId")
              .append("reportType", "product")
              .append("cveId", "$_id.cveId")
              .append("repositoriesAnalyzed",
                  new Document("$concat", Arrays.asList(
                      new Document("$toString", "$completed"),
                      "/",
                      new Document("$toString", "$total"),
                      " analyzed")))
              .append("statuses", "$statuses")
              .append("completedAt", "$earliestCompletedAt")
              .append("submittedAt", "$earliestSubmittedAt")
              .append("mongoId", new Document("$toString", "$firstMongoId"))));
}

/**
 * Build the component pipeline (for $facet)
 */
private List<Document> buildComponentPipeline() {
  return Arrays.asList(
      new Document("$match", new Document("hasProductId", false)),
      new Document("$addFields",
          new Document("cveToUnwind",
              new Document("$cond", Arrays.asList(
                  new Document("$and", Arrays.asList(
                      new Document("$ne", Arrays.asList("$input.scan.vulns", null)),
                      new Document("$gt", Arrays.asList(
                          new Document("$size",
                              new Document("$ifNull", Arrays.asList("$input.scan.vulns", new ArrayList<>()))),
                          0)))),
                  "$input.scan.vulns",
                  Arrays.asList(new Document("vuln_id", "-")))))),
      new Document("$unwind", "$cveToUnwind"),
      new Document("$addFields",
          new Document("outputArray",
              new Document("$ifNull", Arrays.asList("$output", new ArrayList<>())))),
      new Document("$addFields",
          new Document("matchedOutput",
              new Document("$filter", new Document("input", "$outputArray")
                  .append("as", "out")
                  .append("cond", new Document("$eq", Arrays.asList(
                      "$$out.vuln_id",
                      "$cveToUnwind.vuln_id")))))),
      new Document("$addFields",
          new Document("firstMatchedOutput",
              new Document("$arrayElemAt", Arrays.asList("$matchedOutput", 0)))),
      new Document("$project",
          new Document("reportId", "$input.scan.id")
              .append("reportType", "component")
              .append("cveId",
                  new Document("$ifNull", Arrays.asList(
                      "$cveToUnwind.vuln_id",
                      "-")))
              .append("repositoriesAnalyzed", "1")
              .append("justificationStatus",
                  new Document("$ifNull", Arrays.asList(
                      "$firstMatchedOutput.justification.status",
                      null)))
              .append("completedAt", "$input.scan.completed_at")
              .append("submittedAt", "$metadata.submitted_at")
              .append("mongoId", new Document("$toString", "$_id"))));
}

/**
 * Get total count using a single count pipeline
 */
private long getTotalCount(Bson baseFilter) {
  List<Bson> countPipeline = new ArrayList<>();
  countPipeline.add(Aggregates.match(baseFilter));
  countPipeline.add(new Document("$addFields",
      new Document("hasProductId",
          new Document("$and", Arrays.asList(
              new Document("$ne", Arrays.asList("$metadata.product_id", null)),
              new Document("$ne", Arrays.asList("$metadata.product_id", "")))))));
  countPipeline.add(new Document("$facet",
      new Document("products", Arrays.asList(
          new Document("$match", new Document("hasProductId", true)),
          new Document("$unwind", "$input.scan.vulns"),
          new Document("$group",
              new Document("_id",
                  new Document("productId", "$metadata.product_id")
                      .append("cveId", "$input.scan.vulns.vuln_id"))),
          new Document("$count", "count")))
          .append("components", Arrays.asList(
              new Document("$match", new Document("hasProductId", false)),
              new Document("$unwind", "$input.scan.vulns"),
              new Document("$count", "count")))));
  countPipeline.add(new Document("$project",
      new Document("total",
          new Document("$add", Arrays.asList(
              new Document("$ifNull", Arrays.asList(
                  new Document("$arrayElemAt", Arrays.asList("$products.count", 0)), 0)),
              new Document("$ifNull", Arrays.asList(
                  new Document("$arrayElemAt", Arrays.asList("$components.count", 0)), 0)))))));

  Document countDoc = getCollection()
      .aggregate(countPipeline, Document.class)
      .first();
  
  return (countDoc != null && countDoc.get("total") != null)
      ? countDoc.getInteger("total", 0)
      : 0;
}
