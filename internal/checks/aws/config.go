package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/complykit/complykit/internal/engine"
)

type AWSConfigChecker struct {
	client *configservice.Client
}

func NewAWSConfigChecker(cfg aws.Config) *AWSConfigChecker {
	return &AWSConfigChecker{client: configservice.NewFromConfig(cfg)}
}

func (c *AWSConfigChecker) Integration() string { return "AWS/Config" }

func (c *AWSConfigChecker) Run() ([]engine.Finding, error) {
	recorders, err := c.client.DescribeConfigurationRecorders(context.Background(), &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return []engine.Finding{skip("aws_config_enabled", "AWS Config Enabled", err.Error())}, nil
	}

	if len(recorders.ConfigurationRecorders) == 0 {
		return []engine.Finding{fail(
			"aws_config_enabled", "AWS Config is not configured in this region",
			"AWS/Config", "account", SeverityHigh,
			"Enable AWS Config:\n  aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/config-role\n  aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=my-config-bucket\n  aws configservice start-configuration-recorder --configuration-recorder-name default",
			soc2("CC7.2"), cis("3.5"),
		)}, nil
	}

	statuses, err := c.client.DescribeConfigurationRecorderStatus(context.Background(), &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return []engine.Finding{skip("aws_config_enabled", "AWS Config Status", err.Error())}, nil
	}

	for _, s := range statuses.ConfigurationRecordersStatus {
		if !s.Recording {
			return []engine.Finding{fail(
				"aws_config_enabled", "AWS Config recorder is not recording",
				"AWS/Config", "account", SeverityHigh,
				"Start the Config recorder:\n  aws configservice start-configuration-recorder --configuration-recorder-name default",
				soc2("CC7.2"), cis("3.5"),
			)}, nil
		}
	}

	return []engine.Finding{pass("aws_config_enabled", "AWS Config is enabled and recording", "AWS/Config", "account",
		soc2("CC7.2"), cis("3.5"))}, nil
}
