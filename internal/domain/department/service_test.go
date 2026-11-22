package department_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Florencea/erp-rbac/internal/db"
	"github.com/Florencea/erp-rbac/internal/domain/department"
)

func TestDepartmentTreeHierarchyAndCycleProtection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(dir, "app.sqlite"), filepath.Join(dir, "audit.sqlite"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := db.Seed(ctx, store, db.SeedOptions{AdminPassword: "AdminPass123!"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc := department.NewService(store.AppWrite, store.AppRead)
	tree, err := svc.ListTree(ctx)
	if err != nil || len(tree) < 3 {
		t.Fatalf("expected seeded tree with >=3 nodes, got %d err=%v", len(tree), err)
	}
	rootID := tree[0].ID
	engID := tree[1].ID
	salesID := tree[2].ID

	// Create sub-department under Eng
	sub, err := svc.Create(ctx, department.Input{Name: "平台組", ParentID: &engID, Sort: 1})
	if err != nil {
		t.Fatalf("create sub dept: %v", err)
	}
	expectedSubPath := tree[1].Path + "4/"
	if sub.Path != expectedSubPath {
		t.Fatalf("expected path %q, got %q", expectedSubPath, sub.Path)
	}

	// Cycle protection: cannot set root's parent to its child or grandchild
	if _, err := svc.Update(ctx, rootID, department.Input{Name: "總部", ParentID: &sub.ID, Sort: 1}); !errors.Is(err, department.ErrParentInvalid) {
		t.Fatalf("expected ErrParentInvalid on cycle, got %v", err)
	}
	// Self-parent protection
	if _, err := svc.Update(ctx, engID, department.Input{Name: "研發部", ParentID: &engID, Sort: 1}); !errors.Is(err, department.ErrParentInvalid) {
		t.Fatalf("expected ErrParentInvalid on self-parent, got %v", err)
	}

	// Move Eng under Sales -> sub's materialized path must cascade update
	movedEng, err := svc.Update(ctx, engID, department.Input{Name: "研發部", ParentID: &salesID, Sort: 1})
	if err != nil {
		t.Fatalf("move eng under sales: %v", err)
	}
	updatedSub, err := svc.GetByID(ctx, sub.ID)
	if err != nil {
		t.Fatalf("get sub: %v", err)
	}
	if updatedSub.Path != movedEng.Path+"4/" {
		t.Fatalf("expected cascaded path %q, got %q", movedEng.Path+"4/", updatedSub.Path)
	}

	// Cannot delete dept with children
	if err := svc.Delete(ctx, engID); !errors.Is(err, department.ErrHasChildren) {
		t.Fatalf("expected ErrHasChildren, got %v", err)
	}
	// Cannot delete childless dept that still has assigned users
	leaf, err := svc.Create(ctx, department.Input{Name: "稽核室", ParentID: &salesID, Sort: 2})
	if err != nil {
		t.Fatalf("create leaf dept: %v", err)
	}
	if _, err := store.AppWrite.ExecContext(
		ctx,
		`INSERT INTO users (uid, account, password_hash, status, department_id, is_system, created_at, updated_at)
		 VALUES ('u-leaf-1', 'leaf_user', 'hash', 'active', ?, 0, 1, 1)`,
		leaf.ID,
	); err != nil {
		t.Fatalf("insert test user in leaf dept: %v", err)
	}
	if err := svc.Delete(ctx, leaf.ID); !errors.Is(err, department.ErrHasUsers) {
		t.Fatalf("expected ErrHasUsers, got %v", err)
	}
	if _, err := store.AppWrite.ExecContext(ctx, `DELETE FROM users WHERE account = 'leaf_user'`); err != nil {
		t.Fatalf("cleanup test user: %v", err)
	}
	if err := svc.Delete(ctx, leaf.ID); err != nil {
		t.Fatalf("delete empty leaf dept after user removal: %v", err)
	}
	// Can delete empty leaf sub-dept
	if err := svc.Delete(ctx, sub.ID); err != nil {
		t.Fatalf("delete empty leaf sub-dept: %v", err)
	}
}
