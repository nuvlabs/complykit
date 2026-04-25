package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/complykit/complykit/internal/engine"
)

type WAFChecker struct {
	waf  *wafv2.Client
	elbv2 *elasticloadbalancingv2.Client
}

func NewWAFChecker(cfg aws.Config) *WAFChecker {
	return &WAFChecker{
		waf:  wafv2.NewFromConfig(cfg),
		elbv2: elasticloadbalancingv2.NewFromConfig(cfg),
	}
}

func (c *WAFChecker) Integration() string { return "AWS/WAF" }

func (c *WAFChecker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	findings = append(findings, c.checkWAFEnabled()...)
	findings = append(findings, c.checkALBHTTPS()...)
	return findings, nil
}

// ── WAF associated with ALB/CloudFront ────────────────────────────────────────

func (c *WAFChecker) checkWAFEnabled() []engine.Finding {
	// List regional WAFs (for ALBs)
	regional, err := c.waf.ListWebACLs(context.Background(), &wafv2.ListWebACLsInput{
		Scope: waftypes.ScopeRegional,
	})
	if err != nil {
		return []engine.Finding{skip("aws_waf_enabled", "AWS WAF Enabled", err.Error())}
	}

	if len(regional.WebACLs) == 0 {
		return []engine.Finding{fail(
			"aws_waf_enabled", "No WAFv2 regional Web ACLs found",
			"AWS/WAF", "account", SeverityHigh,
			"Create a WAF Web ACL and associate it with your ALBs and API Gateways:\n  aws wafv2 create-web-acl --name MyWebACL --scope REGIONAL --default-action Allow={} ...",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"),
		)}
	}

	// Check that at least one ALB is associated with a WAF
	albs, err := c.elbv2.DescribeLoadBalancers(context.Background(), &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil || len(albs.LoadBalancers) == 0 {
		return []engine.Finding{pass("aws_waf_enabled",
			fmt.Sprintf("%d WAFv2 Web ACL(s) configured (no ALBs to associate)", len(regional.WebACLs)),
			"AWS/WAF", "account", soc2("CC6.6"), hipaa("164.312(e)(2)(i)"))}
	}

	var unprotected []string
	for _, lb := range albs.LoadBalancers {
		if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
			continue
		}
		arn := aws.ToString(lb.LoadBalancerArn)
		resources, err := c.waf.ListResourcesForWebACL(context.Background(), &wafv2.ListResourcesForWebACLInput{
			WebACLArn:    regional.WebACLs[0].ARN,
			ResourceType: waftypes.ResourceTypeApplicationLoadBalancer,
		})
		if err != nil {
			unprotected = append(unprotected, aws.ToString(lb.LoadBalancerName))
			continue
		}
		found := false
		for _, r := range resources.ResourceArns {
			if r == arn {
				found = true
				break
			}
		}
		if !found {
			unprotected = append(unprotected, aws.ToString(lb.LoadBalancerName))
		}
	}

	if len(unprotected) == 0 {
		return []engine.Finding{pass("aws_waf_enabled",
			fmt.Sprintf("WAFv2 configured — %d Web ACL(s) found and ALBs associated", len(regional.WebACLs)),
			"AWS/WAF", "account", soc2("CC6.6"), hipaa("164.312(e)(2)(i)"))}
	}
	return []engine.Finding{fail(
		"aws_waf_enabled",
		fmt.Sprintf("%d ALB(s) not protected by WAF: %v", len(unprotected), truncateList(unprotected, 5)),
		"AWS/WAF", fmt.Sprintf("%d ALBs", len(unprotected)), SeverityHigh,
		"Associate a WAF Web ACL with each ALB:\n  aws wafv2 associate-web-acl --web-acl-arn ACL_ARN --resource-arn ALB_ARN",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"),
	)}
}

// ── ALB HTTPS-only ────────────────────────────────────────────────────────────

func (c *WAFChecker) checkALBHTTPS() []engine.Finding {
	albs, err := c.elbv2.DescribeLoadBalancers(context.Background(), &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return []engine.Finding{skip("aws_alb_https_only", "ALB HTTPS Only", err.Error())}
	}

	var httpOnly []string
	for _, lb := range albs.LoadBalancers {
		if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
			continue
		}
		listeners, err := c.elbv2.DescribeListeners(context.Background(), &elasticloadbalancingv2.DescribeListenersInput{
			LoadBalancerArn: lb.LoadBalancerArn,
		})
		if err != nil {
			continue
		}
		for _, l := range listeners.Listeners {
			if aws.ToInt32(l.Port) == 80 {
				// Check if the HTTP listener redirects to HTTPS
				isRedirect := false
				for _, action := range l.DefaultActions {
					if action.RedirectConfig != nil &&
						strings.EqualFold(aws.ToString(action.RedirectConfig.Protocol), "HTTPS") {
						isRedirect = true
						break
					}
				}
				if !isRedirect {
					httpOnly = append(httpOnly, aws.ToString(lb.LoadBalancerName))
					break
				}
			}
		}
	}

	if len(albs.LoadBalancers) == 0 {
		return []engine.Finding{pass("aws_alb_https_only", "No ALBs found", "AWS/WAF", "account",
			soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"))}
	}
	if len(httpOnly) == 0 {
		return []engine.Finding{pass("aws_alb_https_only", "All ALBs redirect HTTP to HTTPS or have no HTTP listener", "AWS/WAF", "albs",
			soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"))}
	}
	return []engine.Finding{fail(
		"aws_alb_https_only",
		fmt.Sprintf("%d ALB(s) have HTTP port 80 without HTTPS redirect: %v", len(httpOnly), truncateList(httpOnly, 5)),
		"AWS/WAF", fmt.Sprintf("%d ALBs", len(httpOnly)), SeverityHigh,
		"Add an HTTP→HTTPS redirect rule to the port 80 listener:\n  aws elbv2 create-rule --listener-arn HTTP_LISTENER_ARN \\\n    --conditions Field=path-pattern,Values='*' \\\n    --actions Type=redirect,RedirectConfig='{Protocol=HTTPS,StatusCode=HTTP_301}'",
		soc2("CC6.7"), hipaa("164.312(e)(2)(ii)"),
	)}
}
