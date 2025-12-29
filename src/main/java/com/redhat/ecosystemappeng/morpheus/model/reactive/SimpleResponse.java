package com.redhat.ecosystemappeng.morpheus.model.reactive;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SimpleResponse {
    public List<ResponseItem> responses;
    public long totalExecutionTimeMs;
    public int totalRequests;

    public SimpleResponse() {
    }

    public SimpleResponse(List<ResponseItem> responses, long totalExecutionTimeMs, int totalRequests) {
        this.responses = responses;
        this.totalExecutionTimeMs = totalExecutionTimeMs;
        this.totalRequests = totalRequests;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ResponseItem {
        public int requestId;
        public String status;
        public Object data;

        public ResponseItem() {
        }

        public ResponseItem(int requestId, String status, Object data) {
            this.requestId = requestId;
            this.status = status;
            this.data = data;
        }
    }
}

