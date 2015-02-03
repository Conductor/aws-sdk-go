// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT.

// Package cloudtrail provides a client for AWS CloudTrail.
package cloudtrail

import (
	"net/http"
	"time"

	"github.com/Conductor/aws-sdk-go/aws"
	"github.com/Conductor/aws-sdk-go/gen/endpoints"
)

// CloudTrail is a client for AWS CloudTrail.
type CloudTrail struct {
	client *aws.JSONClient
}

// New returns a new CloudTrail client.
func New(creds aws.CredentialsProvider, region string, client *http.Client) *CloudTrail {
	if client == nil {
		client = http.DefaultClient
	}

	endpoint, service, region := endpoints.Lookup("cloudtrail", region)

	return &CloudTrail{
		client: &aws.JSONClient{
			Context: aws.Context{
				Credentials: creds,
				Service:     service,
				Region:      region,
			}, Client: client,
			Endpoint:     endpoint,
			JSONVersion:  "1.1",
			TargetPrefix: "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101",
		},
	}
}

// CreateTrail from the command line, use create-subscription . Creates a
// trail that specifies the settings for delivery of log data to an Amazon
// S3 bucket.
func (c *CloudTrail) CreateTrail(req *CreateTrailRequest) (resp *CreateTrailResponse, err error) {
	resp = &CreateTrailResponse{}
	err = c.client.Do("CreateTrail", "POST", "/", req, resp)
	return
}

// DeleteTrail is undocumented.
func (c *CloudTrail) DeleteTrail(req *DeleteTrailRequest) (resp *DeleteTrailResponse, err error) {
	resp = &DeleteTrailResponse{}
	err = c.client.Do("DeleteTrail", "POST", "/", req, resp)
	return
}

// DescribeTrails retrieves settings for the trail associated with the
// current region for your account.
func (c *CloudTrail) DescribeTrails(req *DescribeTrailsRequest) (resp *DescribeTrailsResponse, err error) {
	resp = &DescribeTrailsResponse{}
	err = c.client.Do("DescribeTrails", "POST", "/", req, resp)
	return
}

// GetTrailStatus returns a JSON-formatted list of information about the
// specified trail. Fields include information on delivery errors, Amazon
// SNS and Amazon S3 errors, and start and stop logging times for each
// trail.
func (c *CloudTrail) GetTrailStatus(req *GetTrailStatusRequest) (resp *GetTrailStatusResponse, err error) {
	resp = &GetTrailStatusResponse{}
	err = c.client.Do("GetTrailStatus", "POST", "/", req, resp)
	return
}

// StartLogging starts the recording of AWS API calls and log file delivery
// for a trail.
func (c *CloudTrail) StartLogging(req *StartLoggingRequest) (resp *StartLoggingResponse, err error) {
	resp = &StartLoggingResponse{}
	err = c.client.Do("StartLogging", "POST", "/", req, resp)
	return
}

// StopLogging suspends the recording of AWS API calls and log file
// delivery for the specified trail. Under most circumstances, there is no
// need to use this action. You can update a trail without stopping it
// first. This action is the only way to stop recording.
func (c *CloudTrail) StopLogging(req *StopLoggingRequest) (resp *StopLoggingResponse, err error) {
	resp = &StopLoggingResponse{}
	err = c.client.Do("StopLogging", "POST", "/", req, resp)
	return
}

// UpdateTrail from the command line, use update-subscription Updates the
// settings that specify delivery of log files. Changes to a trail do not
// require stopping the CloudTrail service. Use this action to designate an
// existing bucket for log delivery. If the existing bucket has previously
// been a target for CloudTrail log files, an IAM policy exists for the
// bucket.
func (c *CloudTrail) UpdateTrail(req *UpdateTrailRequest) (resp *UpdateTrailResponse, err error) {
	resp = &UpdateTrailResponse{}
	err = c.client.Do("UpdateTrail", "POST", "/", req, resp)
	return
}

// CreateTrailRequest is undocumented.
type CreateTrailRequest struct {
	CloudWatchLogsLogGroupARN  aws.StringValue  `json:"CloudWatchLogsLogGroupArn,omitempty"`
	CloudWatchLogsRoleARN      aws.StringValue  `json:"CloudWatchLogsRoleArn,omitempty"`
	IncludeGlobalServiceEvents aws.BooleanValue `json:"IncludeGlobalServiceEvents,omitempty"`
	Name                       aws.StringValue  `json:"Name"`
	S3BucketName               aws.StringValue  `json:"S3BucketName"`
	S3KeyPrefix                aws.StringValue  `json:"S3KeyPrefix,omitempty"`
	SNSTopicName               aws.StringValue  `json:"SnsTopicName,omitempty"`
}

// CreateTrailResponse is undocumented.
type CreateTrailResponse struct {
	CloudWatchLogsLogGroupARN  aws.StringValue  `json:"CloudWatchLogsLogGroupArn,omitempty"`
	CloudWatchLogsRoleARN      aws.StringValue  `json:"CloudWatchLogsRoleArn,omitempty"`
	IncludeGlobalServiceEvents aws.BooleanValue `json:"IncludeGlobalServiceEvents,omitempty"`
	Name                       aws.StringValue  `json:"Name,omitempty"`
	S3BucketName               aws.StringValue  `json:"S3BucketName,omitempty"`
	S3KeyPrefix                aws.StringValue  `json:"S3KeyPrefix,omitempty"`
	SNSTopicName               aws.StringValue  `json:"SnsTopicName,omitempty"`
}

// DeleteTrailRequest is undocumented.
type DeleteTrailRequest struct {
	Name aws.StringValue `json:"Name"`
}

// DeleteTrailResponse is undocumented.
type DeleteTrailResponse struct {
}

// DescribeTrailsRequest is undocumented.
type DescribeTrailsRequest struct {
	TrailNameList []string `json:"trailNameList,omitempty"`
}

// DescribeTrailsResponse is undocumented.
type DescribeTrailsResponse struct {
	TrailList []Trail `json:"trailList,omitempty"`
}

// GetTrailStatusRequest is undocumented.
type GetTrailStatusRequest struct {
	Name aws.StringValue `json:"Name"`
}

// GetTrailStatusResponse is undocumented.
type GetTrailStatusResponse struct {
	IsLogging                         aws.BooleanValue `json:"IsLogging,omitempty"`
	LatestCloudWatchLogsDeliveryError aws.StringValue  `json:"LatestCloudWatchLogsDeliveryError,omitempty"`
	LatestCloudWatchLogsDeliveryTime  time.Time        `json:"LatestCloudWatchLogsDeliveryTime,omitempty"`
	LatestDeliveryError               aws.StringValue  `json:"LatestDeliveryError,omitempty"`
	LatestDeliveryTime                time.Time        `json:"LatestDeliveryTime,omitempty"`
	LatestNotificationError           aws.StringValue  `json:"LatestNotificationError,omitempty"`
	LatestNotificationTime            time.Time        `json:"LatestNotificationTime,omitempty"`
	StartLoggingTime                  time.Time        `json:"StartLoggingTime,omitempty"`
	StopLoggingTime                   time.Time        `json:"StopLoggingTime,omitempty"`
}

// StartLoggingRequest is undocumented.
type StartLoggingRequest struct {
	Name aws.StringValue `json:"Name"`
}

// StartLoggingResponse is undocumented.
type StartLoggingResponse struct {
}

// StopLoggingRequest is undocumented.
type StopLoggingRequest struct {
	Name aws.StringValue `json:"Name"`
}

// StopLoggingResponse is undocumented.
type StopLoggingResponse struct {
}

// Trail is undocumented.
type Trail struct {
	CloudWatchLogsLogGroupARN  aws.StringValue  `json:"CloudWatchLogsLogGroupArn,omitempty"`
	CloudWatchLogsRoleARN      aws.StringValue  `json:"CloudWatchLogsRoleArn,omitempty"`
	IncludeGlobalServiceEvents aws.BooleanValue `json:"IncludeGlobalServiceEvents,omitempty"`
	Name                       aws.StringValue  `json:"Name,omitempty"`
	S3BucketName               aws.StringValue  `json:"S3BucketName,omitempty"`
	S3KeyPrefix                aws.StringValue  `json:"S3KeyPrefix,omitempty"`
	SNSTopicName               aws.StringValue  `json:"SnsTopicName,omitempty"`
}

// UpdateTrailRequest is undocumented.
type UpdateTrailRequest struct {
	CloudWatchLogsLogGroupARN  aws.StringValue  `json:"CloudWatchLogsLogGroupArn,omitempty"`
	CloudWatchLogsRoleARN      aws.StringValue  `json:"CloudWatchLogsRoleArn,omitempty"`
	IncludeGlobalServiceEvents aws.BooleanValue `json:"IncludeGlobalServiceEvents,omitempty"`
	Name                       aws.StringValue  `json:"Name"`
	S3BucketName               aws.StringValue  `json:"S3BucketName,omitempty"`
	S3KeyPrefix                aws.StringValue  `json:"S3KeyPrefix,omitempty"`
	SNSTopicName               aws.StringValue  `json:"SnsTopicName,omitempty"`
}

// UpdateTrailResponse is undocumented.
type UpdateTrailResponse struct {
	CloudWatchLogsLogGroupARN  aws.StringValue  `json:"CloudWatchLogsLogGroupArn,omitempty"`
	CloudWatchLogsRoleARN      aws.StringValue  `json:"CloudWatchLogsRoleArn,omitempty"`
	IncludeGlobalServiceEvents aws.BooleanValue `json:"IncludeGlobalServiceEvents,omitempty"`
	Name                       aws.StringValue  `json:"Name,omitempty"`
	S3BucketName               aws.StringValue  `json:"S3BucketName,omitempty"`
	S3KeyPrefix                aws.StringValue  `json:"S3KeyPrefix,omitempty"`
	SNSTopicName               aws.StringValue  `json:"SnsTopicName,omitempty"`
}

// avoid errors if the packages aren't referenced
var _ time.Time
