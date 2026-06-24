package server

import (
	"context"
	"fmt"
	"time"

	pb "github.com/L1566/FileGuard/api/proto/audit"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuditServer 实现 audit.AuditServiceServer 接口
type AuditServer struct {
	pb.UnimplementedAuditServiceServer
	logger *audit.FileLogger
}

// NewAuditServer 创建审计 gRPC 服务端
func NewAuditServer(logger *audit.FileLogger) *AuditServer {
	return &AuditServer{logger: logger}
}

// Log 记录一条审计事件
func (s *AuditServer) Log(ctx context.Context, req *pb.LogRequest) (*pb.LogResponse, error) {
	if req.Event == nil {
		return nil, status.Error(codes.InvalidArgument, "event is required")
	}
	event := protoToAuditEvent(req.Event)
	if err := s.logger.Log(ctx, event); err != nil {
		return nil, status.Errorf(codes.Internal, "log failed: %v", err)
	}
	return &pb.LogResponse{
		Success: true,
		EventId: event.ID,
	}, nil
}

// Query 查询审计事件
func (s *AuditServer) Query(ctx context.Context, req *pb.QueryRequest) (*pb.QueryResponse, error) {
	filter := audit.Filter{
		SubjectID:  req.SubjectId,
		ResourceID: req.ResourcePath,
		EventType:  audit.EventType(req.EventType),
		Limit:      int(req.Limit),
		Offset:     int(req.Offset),
	}
	if req.StartTime != nil {
		t := req.StartTime.AsTime()
		filter.StartTime = &t
	}
	if req.EndTime != nil {
		t := req.EndTime.AsTime()
		filter.EndTime = &t
	}

	events, err := s.logger.Query(ctx, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query failed: %v", err)
	}

	pbEvents := make([]*pb.AuditEvent, len(events))
	for i, e := range events {
		pbEvents[i] = auditEventToProto(&e)
	}

	return &pb.QueryResponse{
		Events: pbEvents,
		Total:  int32(len(pbEvents)),
	}, nil
}

// =============================================================================
// Proto <-> Go 类型转换
// =============================================================================

func protoToAuditEvent(pe *pb.AuditEvent) audit.AuditEvent {
	e := audit.AuditEvent{
		ID:        pe.Id,
		EventType: audit.EventType(pe.EventType),
		Subject: abac.Subject{
			ID:   pe.SubjectId,
			Role: pe.SubjectRole,
		},
		Resource: abac.Resource{
			Path:        pe.ResourcePath,
			Sensitivity: pe.ResourceSensitivity,
		},
		Environment: abac.Environment{
			IP: pe.EnvironmentIp,
		},
		Decision: abac.Decision{
			Allowed: pe.Allowed,
			Reason:  pe.Reason,
		},
		Result: pe.Result,
	}
	if pe.Timestamp != nil {
		e.Timestamp = pe.Timestamp.AsTime()
	} else {
		e.Timestamp = time.Now()
	}
	if len(pe.Details) > 0 {
		e.Details = make(map[string]interface{}, len(pe.Details))
		for k, v := range pe.Details {
			e.Details[k] = v
		}
	}
	return e
}

func auditEventToProto(e *audit.AuditEvent) *pb.AuditEvent {
	pe := &pb.AuditEvent{
		Id:                  e.ID,
		Timestamp:           timestamppb.New(e.Timestamp),
		EventType:           string(e.EventType),
		SubjectId:           e.Subject.ID,
		SubjectRole:         e.Subject.Role,
		ResourcePath:        e.Resource.Path,
		ResourceSensitivity: e.Resource.Sensitivity,
		EnvironmentIp:       e.Environment.IP,
		Allowed:             e.Decision.Allowed,
		Reason:              e.Decision.Reason,
		Result:              e.Result,
	}
	if len(e.Details) > 0 {
		pe.Details = make(map[string]string, len(e.Details))
		for k, v := range e.Details {
			pe.Details[k] = fmt.Sprintf("%v", v)
		}
	}
	return pe
}
