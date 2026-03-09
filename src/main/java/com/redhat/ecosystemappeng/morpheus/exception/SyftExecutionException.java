package com.redhat.ecosystemappeng.morpheus.exception;

/**
 * Exception thrown when syft command execution fails.
 * Extends IOException to maintain compatibility with existing error handling.
 */
public class SyftExecutionException extends RuntimeException {
    
    private final String image;
    
    public SyftExecutionException(String image, String message) {
        super(message);
        this.image = image;
    }
    
    public SyftExecutionException(String target, String message, Throwable cause) {
        super(message, cause);
        this.image = target;
    }
    
    /**
     * Get the syft target that failed
     */
    public String getImage() {
        return image;
    }
}

