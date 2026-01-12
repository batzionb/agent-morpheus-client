package com.redhat.ecosystemappeng.morpheus.exception;

/**
 * Exception thrown when component syncer submission fails
 */
public class ComponentSyncerSubmitException extends RuntimeException {
    
    private final String reportId;
    
    public ComponentSyncerSubmitException(String reportId, String message) {
        super(message);
        this.reportId = reportId;
    }
    
    public ComponentSyncerSubmitException(String reportId, String message, Throwable cause) {
        super(message, cause);
        this.reportId = reportId;
    }
    
    /**
     * Get the report ID that failed to submit
     */
    public String getReportId() {
        return reportId;
    }
}

