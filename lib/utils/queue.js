/**
 * Simple job queue to manage concurrent processing
 * Prevents server overload with many simultaneous requests
 */
class JobQueue {
  constructor(options = {}) {
    this.concurrency = options.concurrency || 3; // Max concurrent jobs
    this.maxQueue = options.maxQueue || 50; // Max jobs waiting before we shed load
    this.running = 0;
    this.queue = [];
    this.results = new Map();
  }

  /**
   * Add a job to the queue
   * @param {string} id - Unique job identifier
   * @param {Function} jobFn - Async function to execute
   * @returns {Promise} - Resolves when job completes
   */
  async enqueue(id, jobFn) {
    // Check if job is already queued or running
    if (this.results.has(id)) {
      return this.results.get(id);
    }

    // Backpressure: shed load instead of letting the waiting queue (and memory)
    // grow without bound under a traffic spike.
    if (this.queue.length >= this.maxQueue) {
      const err = new Error('Analysis queue is full, please try again shortly');
      err.code = 'QUEUE_FULL';
      err.statusCode = 503;
      throw err;
    }

    // Create a promise for this job
    const jobPromise = new Promise((resolve, reject) => {
      this.queue.push({
        id,
        jobFn,
        resolve,
        reject
      });
    });
    
    // Store the promise so we can return it for duplicate requests
    this.results.set(id, jobPromise);
    
    // Try to process the queue
    this.processQueue();
    
    return jobPromise;
  }
  
  /**
   * Process jobs in the queue if capacity available
   */
  async processQueue() {
    if (this.running >= this.concurrency || this.queue.length === 0) {
      return;
    }
    
    // Get the next job
    const job = this.queue.shift();
    this.running++;
    
    try {
      // Execute the job
      const result = await job.jobFn();
      job.resolve(result);
    } catch (error) {
      job.reject(error);
    } finally {
      this.running--;
      this.results.delete(job.id);
      
      // Process next job
      this.processQueue();
    }
  }
  
  /**
   * Get the current queue status
   */
  getStatus() {
    return {
      running: this.running,
      queued: this.queue.length,
      total: this.running + this.queue.length
    };
  }
}

// Create a singleton instance
const domainQueue = new JobQueue({ concurrency: 3 });

module.exports = domainQueue; 