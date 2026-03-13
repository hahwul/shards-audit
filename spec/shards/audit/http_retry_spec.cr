require "../../spec_helper"

class RetryTestHelper
  include Shards::Audit::HttpRetry

  getter attempts : Int32 = 0

  def initialize(@verbose : Bool = false)
  end

  def attempt_with_retry(fail_count : Int32, max_retries : Int32 = 3) : String
    with_retry(max_retries: max_retries, base_delay: 0.01) do
      @attempts += 1
      if @attempts <= fail_count
        raise IO::Error.new("connection failed")
      end
      "success"
    end
  end

  def attempt_with_timeout_error(fail_count : Int32, max_retries : Int32 = 3) : String
    with_retry(max_retries: max_retries, base_delay: 0.01) do
      @attempts += 1
      if @attempts <= fail_count
        raise IO::TimeoutError.new("read timed out")
      end
      "success"
    end
  end

  def attempt_with_connect_error(fail_count : Int32, max_retries : Int32 = 3) : String
    with_retry(max_retries: max_retries, base_delay: 0.01) do
      @attempts += 1
      if @attempts <= fail_count
        raise Socket::ConnectError.new("connection refused")
      end
      "success"
    end
  end

  def attempt_with_non_retryable_error : String
    with_retry(max_retries: 3, base_delay: 0.01) do
      @attempts += 1
      raise ArgumentError.new("bad argument")
    end
  end
end

describe Shards::Audit::HttpRetry do
  it "succeeds on first attempt" do
    helper = RetryTestHelper.new
    result = helper.attempt_with_retry(fail_count: 0)
    result.should eq("success")
    helper.attempts.should eq(1)
  end

  it "succeeds after retries" do
    helper = RetryTestHelper.new
    result = helper.attempt_with_retry(fail_count: 2)
    result.should eq("success")
    helper.attempts.should eq(3)
  end

  it "raises after max retries exceeded" do
    helper = RetryTestHelper.new
    expect_raises(IO::Error) do
      helper.attempt_with_retry(fail_count: 5, max_retries: 3)
    end
    helper.attempts.should eq(4) # initial + 3 retries
  end

  it "retries on IO::TimeoutError" do
    helper = RetryTestHelper.new
    result = helper.attempt_with_timeout_error(fail_count: 1)
    result.should eq("success")
    helper.attempts.should eq(2)
  end

  it "raises IO::TimeoutError after max retries" do
    helper = RetryTestHelper.new
    expect_raises(IO::TimeoutError) do
      helper.attempt_with_timeout_error(fail_count: 5, max_retries: 2)
    end
    helper.attempts.should eq(3)
  end

  it "retries on Socket::ConnectError" do
    helper = RetryTestHelper.new
    result = helper.attempt_with_connect_error(fail_count: 1)
    result.should eq("success")
    helper.attempts.should eq(2)
  end

  it "raises Socket::ConnectError after max retries" do
    helper = RetryTestHelper.new
    expect_raises(Socket::ConnectError) do
      helper.attempt_with_connect_error(fail_count: 5, max_retries: 2)
    end
    helper.attempts.should eq(3)
  end

  it "does not retry non-retryable exceptions" do
    helper = RetryTestHelper.new
    expect_raises(ArgumentError) do
      helper.attempt_with_non_retryable_error
    end
    helper.attempts.should eq(1) # no retries
  end

  it "succeeds with max_retries: 1" do
    helper = RetryTestHelper.new
    result = helper.attempt_with_retry(fail_count: 1, max_retries: 1)
    result.should eq("success")
    helper.attempts.should eq(2)
  end

  describe "#retryable_status?" do
    it "returns true for transient server errors" do
      helper = RetryTestHelper.new
      helper.retryable_status?(429).should be_true
      helper.retryable_status?(500).should be_true
      helper.retryable_status?(502).should be_true
      helper.retryable_status?(503).should be_true
      helper.retryable_status?(504).should be_true
    end

    it "returns false for non-retryable status codes" do
      helper = RetryTestHelper.new
      helper.retryable_status?(200).should be_false
      helper.retryable_status?(404).should be_false
      helper.retryable_status?(403).should be_false
      helper.retryable_status?(422).should be_false
    end
  end
end
