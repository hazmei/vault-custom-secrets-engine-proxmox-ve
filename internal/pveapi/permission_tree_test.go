// Package pveapi — unit tests for PermissionTree.HasPrivilege ancestor-walk.
//
// Tests confirm:
//   - Exact-path match (propagate=0) → true
//   - Ancestor match with propagate=1 → true
//   - Ancestor match with propagate=0 → false (CRITICAL: catches --propagate 0 misconfiguration)
//   - Root "/" grant with propagate=1 → satisfies any descendant
//   - Missing path → false
//   - Root "/" exact match → true regardless of propagate
package pveapi

import "testing"

func TestPermissionTreeHasPrivilege(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tree PermissionTree
		path string
		priv string
		want bool
	}{
		// ── Exact path match ──────────────────────────────────────────────
		{
			name: "exact match at /access/groups with propagate=0",
			tree: PermissionTree{
				"/access/groups": {"User.Modify": 0},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: true, // exact match: propagate flag irrelevant
		},
		{
			name: "exact match at /access/groups with propagate=1",
			tree: PermissionTree{
				"/access/groups": {"User.Modify": 1},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: true,
		},
		// ── Ancestor propagate=1 → satisfied ─────────────────────────────
		{
			name: "parent /access grant with propagate=1 satisfies /access/groups",
			tree: PermissionTree{
				"/access": {"User.Modify": 1},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: true,
		},
		{
			name: "root / grant with propagate=1 satisfies /access/groups",
			tree: PermissionTree{
				"/": {"User.Modify": 1},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: true,
		},
		{
			name: "root / grant with propagate=1 satisfies /access/groups/mygroup",
			tree: PermissionTree{
				"/": {"Sys.Audit": 1},
			},
			path: "/access/groups/mygroup",
			priv: "Sys.Audit",
			want: true,
		},
		// ── CRITICAL: Ancestor propagate=0 → NOT satisfied ───────────────
		// This is the --propagate 0 misconfiguration that AGENTS.md warns about.
		// A grant at /access/groups with propagate=0 satisfies /access/groups
		// itself but NOT /access/groups/<child>. More importantly, a grant at
		// /access (parent) with propagate=0 does NOT satisfy /access/groups.
		{
			name: "parent /access grant with propagate=0 does NOT satisfy /access/groups",
			tree: PermissionTree{
				"/access": {"User.Modify": 0},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: false, // propagate=0 at parent → does NOT flow down
		},
		{
			name: "root / grant with propagate=0 does NOT satisfy /access/groups",
			tree: PermissionTree{
				"/": {"User.Modify": 0},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: false,
		},
		// ── Missing path → false ─────────────────────────────────────────
		{
			name: "no entry anywhere → false",
			tree: PermissionTree{},
			path: "/access/groups",
			priv: "User.Modify",
			want: false,
		},
		{
			name: "entry at /access/groups but wrong privilege → false",
			tree: PermissionTree{
				"/access/groups": {"Sys.Audit": 1},
			},
			path: "/access/groups",
			priv: "User.Modify",
			want: false,
		},
		// ── Root "/" exact match ─────────────────────────────────────────
		{
			name: "exact match at root / with propagate=0",
			tree: PermissionTree{
				"/": {"User.Modify": 0},
			},
			path: "/",
			priv: "User.Modify",
			want: true, // exact match at root
		},
		// ── Multi-level ancestor ──────────────────────────────────────────
		{
			name: "grant at /access/groups propagate=1 satisfies /access/groups/mygroup",
			tree: PermissionTree{
				"/access/groups": {"User.Modify": 1},
			},
			path: "/access/groups/mygroup",
			priv: "User.Modify",
			want: true,
		},
		{
			name: "grant at /access/groups propagate=0 does NOT satisfy /access/groups/mygroup",
			tree: PermissionTree{
				"/access/groups": {"User.Modify": 0},
			},
			path: "/access/groups/mygroup",
			priv: "User.Modify",
			want: false, // propagate=0 at parent → does NOT flow to child
		},
		// ── Sys.Audit cases (used in config-write validation) ────────────
		{
			name: "Sys.Audit at /access/groups propagate=1",
			tree: PermissionTree{
				"/access/groups": {"Sys.Audit": 1},
			},
			path: "/access/groups",
			priv: "Sys.Audit",
			want: true,
		},
		{
			name: "both User.Modify and Sys.Audit in same tree entry",
			tree: PermissionTree{
				"/access/groups": {"User.Modify": 1, "Sys.Audit": 1},
			},
			path: "/access/groups",
			priv: "Sys.Audit",
			want: true,
		},
		// ── Realm.AllocateUser (used in role-write validation) ────────────
		{
			name: "Realm.AllocateUser at /access/realm/pve exact match",
			tree: PermissionTree{
				"/access/realm/pve": {"Realm.AllocateUser": 1},
			},
			path: "/access/realm/pve",
			priv: "Realm.AllocateUser",
			want: true,
		},
		{
			name: "Realm.AllocateUser via /access propagate=1",
			tree: PermissionTree{
				"/access": {"Realm.AllocateUser": 1},
			},
			path: "/access/realm/pve",
			priv: "Realm.AllocateUser",
			want: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.tree.HasPrivilege(tc.path, tc.priv)
			if got != tc.want {
				t.Errorf("HasPrivilege(%q, %q) = %v; want %v (tree: %v)",
					tc.path, tc.priv, got, tc.want, tc.tree)
			}
		})
	}
}
