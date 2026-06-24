package server

import (
	"context"
	"fmt"

	pb "github.com/L1566/FileGuard/api/proto/policy"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PolicyServer 实现 policy.PolicyServiceServer 接口
type PolicyServer struct {
	pb.UnimplementedPolicyServiceServer
	evaluator *abac.MemoryEvaluator
	rulesFile string
}

// NewPolicyServer 创建策略 gRPC 服务端
func NewPolicyServer(evaluator *abac.MemoryEvaluator, rulesFile string) *PolicyServer {
	return &PolicyServer{evaluator: evaluator, rulesFile: rulesFile}
}

// Evaluate 评估访问请求
func (s *PolicyServer) Evaluate(ctx context.Context, req *pb.EvaluateRequest) (*pb.EvaluateResponse, error) {
	subject := protoToSubject(req.Subject)
	resource := protoToResource(req.Resource)
	env := protoToEnvironment(req.Environment)

	decision, err := s.evaluator.Evaluate(ctx, subject, resource, env)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "evaluate failed: %v", err)
	}

	return &pb.EvaluateResponse{
		Decision: &pb.Decision{
			Allowed:      decision.Allowed,
			Reason:       decision.Reason,
			Restrictions: decision.Restrictions,
		},
	}, nil
}

// GetRules 获取所有规则
func (s *PolicyServer) GetRules(ctx context.Context, req *pb.GetRulesRequest) (*pb.GetRulesResponse, error) {
	rules := s.evaluator.GetRules()
	pbRules := make([]*pb.Rule, len(rules))
	for i, r := range rules {
		pbRules[i] = ruleToProto(&r)
	}
	return &pb.GetRulesResponse{Rules: pbRules}, nil
}

// AddRule 添加规则
func (s *PolicyServer) AddRule(ctx context.Context, req *pb.AddRuleRequest) (*pb.AddRuleResponse, error) {
	if req.Rule == nil {
		return nil, status.Error(codes.InvalidArgument, "rule is required")
	}
	rule := protoToRule(req.Rule)
	if err := s.evaluator.AddRule(rule); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "add rule failed: %v", err)
	}
	s.persist()
	return &pb.AddRuleResponse{Success: true, RuleId: req.Rule.Id}, nil
}

// UpdateRule 更新规则
func (s *PolicyServer) UpdateRule(ctx context.Context, req *pb.UpdateRuleRequest) (*pb.UpdateRuleResponse, error) {
	if req.Rule == nil {
		return nil, status.Error(codes.InvalidArgument, "rule is required")
	}
	rule := protoToRule(req.Rule)
	if err := s.evaluator.UpdateRule(req.RuleId, rule); err != nil {
		return nil, status.Errorf(codes.NotFound, "update rule failed: %v", err)
	}
	s.persist()
	return &pb.UpdateRuleResponse{Success: true}, nil
}

// DeleteRule 删除规则
func (s *PolicyServer) DeleteRule(ctx context.Context, req *pb.DeleteRuleRequest) (*pb.DeleteRuleResponse, error) {
	s.evaluator.DeleteRule(req.RuleId)
	s.persist()
	return &pb.DeleteRuleResponse{Success: true}, nil
}

func (s *PolicyServer) persist() {
	if s.rulesFile == "" {
		return
	}
	if err := abac.SaveRulesToFile(s.rulesFile, s.evaluator.GetRules()); err != nil {
		logger.Errorf("Failed to persist rules to %s: %v", s.rulesFile, err)
	}
}

// =============================================================================
// Proto <-> Go 类型转换
// =============================================================================

func protoToSubject(ps *pb.Subject) abac.Subject {
	if ps == nil {
		return abac.Subject{}
	}
	return abac.Subject{
		ID:         ps.Id,
		Type:       ps.Type,
		Role:       ps.Role,
		Project:    ps.Project,
		Attributes: stringMapToIface(ps.Attributes),
	}
}

func protoToResource(pr *pb.Resource) abac.Resource {
	if pr == nil {
		return abac.Resource{}
	}
	return abac.Resource{
		ID:          pr.Id,
		Type:        pr.Type,
		Path:        pr.Path,
		Sensitivity: pr.Sensitivity,
		Tags:        pr.Tags,
		Attributes:  stringMapToIface(pr.Attributes),
	}
}

func protoToEnvironment(pe *pb.Environment) abac.Environment {
	if pe == nil {
		return abac.Environment{}
	}
	return abac.Environment{
		Time:       pe.Time,
		IP:         pe.Ip,
		DeviceID:   pe.DeviceId,
		OS:         pe.Os,
		Attributes: stringMapToIface(pe.Attributes),
	}
}

func stringMapToIface(m map[string]string) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func protoToRule(pr *pb.Rule) abac.Rule {
	conditions := make(map[string]interface{}, len(pr.Conditions))
	for k, v := range pr.Conditions {
		conditions[k] = v
	}
	return abac.Rule{
		ID:           pr.Id,
		Effect:       pr.Effect,
		Conditions:   conditions,
		Restrictions: pr.Restrictions,
	}
}

func ruleToProto(r *abac.Rule) *pb.Rule {
	conditions := make(map[string]string, len(r.Conditions))
	for k, v := range r.Conditions {
		conditions[k] = fmt.Sprintf("%v", v)
	}
	return &pb.Rule{
		Id:           r.ID,
		Effect:       r.Effect,
		Conditions:   conditions,
		Restrictions: r.Restrictions,
	}
}
