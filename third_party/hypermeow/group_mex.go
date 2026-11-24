// Consultas de grupo por MEX, como o WhatsApp Web faz desde o bundle 2.3000.1055901559.
// Ver WUZAPI_PATCHES.md, "Link de convite e subgrupos por MEX".

package whatsmeow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/polymorfa/hypermeow/types"
)

// IDs das consultas MEX de grupo do WhatsApp Web, conferidos no bundle 2.3000.1055901559.
const (
	// WAWebMexFetchGroupInviteCodeJobQuery: variables {id, query_context: "INVITE_CODE"},
	// output xwa2_group_query_by_id.invite_code.
	queryFetchGroupInviteCode = "29247029834912157"
	// WAWebMexFetchAllSubgroupsJobQuery: variables {group_id, query_context, sub_group_hint_id},
	// output xwa2_group_query_by_id.{default_sub_group, sub_groups.edges[].node}.
	queryFetchAllSubgroups = "9935467776504344"
)

const (
	groupQueryContextInviteCode  = "INVITE_CODE"
	groupQueryContextInteractive = "INTERACTIVE"

	mexTypeCommunityGroup = "XWA2CommunityGroup"
)

// errMexGroupNotCommunity é devolvido quando o JID consultado em GetCommunitySubGroups não é de comunidade.
var errMexGroupNotCommunity = errors.New("that group is not a community")

type mexGroupSubject struct {
	Value        string          `json:"value"`
	CreationTime json.RawMessage `json:"creation_time"`
}

type mexCommunitySubGroup struct {
	ID         string           `json:"id"`
	Subject    *mexGroupSubject `json:"subject"`
	Properties *struct {
		GeneralChat                   bool `json:"general_chat"`
		MembershipApprovalModeEnabled bool `json:"membership_approval_mode_enabled"`
		HiddenGroup                   bool `json:"hidden_group"`
	} `json:"properties"`
	MembershipApprovalRequests *struct {
		TotalCount int `json:"total_count"`
	} `json:"membership_approval_requests"`
}

type respFetchGroupInviteCode struct {
	Group *struct {
		InviteCode *string `json:"invite_code"`
	} `json:"xwa2_group_query_by_id"`
}

type respFetchAllSubgroups struct {
	Group *struct {
		TypeName        string                `json:"__typename"`
		ID              string                `json:"id"`
		DefaultSubGroup *mexCommunitySubGroup `json:"default_sub_group"`
		SubGroups       *struct {
			Edges []*struct {
				Node *mexCommunitySubGroup `json:"node"`
			} `json:"edges"`
		} `json:"sub_groups"`
	} `json:"xwa2_group_query_by_id"`
}

// mapMexGroupError traduz os códigos de erro do MEX nos mesmos erros que o IQ w:g2 devolvia.
// O segundo valor diz se o erro é uma resposta definitiva do servidor sobre o grupo (sem
// sentido tentar o IQ antigo).
func mapMexGroupError(err error, unauthorized error) (error, bool) {
	var gqlErrs types.GraphQLErrors
	if !errors.As(err, &gqlErrs) {
		return err, false
	}
	for _, gqlErr := range gqlErrs {
		switch gqlErr.Extensions.ErrorCode {
		case 401:
			if unauthorized != nil {
				return wrapIQError(unauthorized, err), true
			}
			return wrapIQError(ErrIQNotAuthorized, err), true
		case 403:
			return wrapIQError(ErrNotInGroup, err), true
		case 404:
			return wrapIQError(ErrGroupNotFound, err), true
		}
	}
	return err, false
}

func (cli *Client) fetchGroupInviteCodeMex(ctx context.Context, jid types.JID) (string, error) {
	data, err := cli.sendMexIQ(ctx, queryFetchGroupInviteCode, map[string]any{
		"id":            jid.String(),
		"query_context": groupQueryContextInviteCode,
	})
	if err != nil {
		return "", err
	}
	var resp respFetchGroupInviteCode
	if err = json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("failed to parse group invite code response: %w", err)
	}
	if resp.Group == nil || resp.Group.InviteCode == nil || *resp.Group.InviteCode == "" {
		return "", fmt.Errorf("group invite code is null in mex response")
	}
	return *resp.Group.InviteCode, nil
}

// GetCommunitySubGroups lista os grupos da comunidade pela consulta MEX do WhatsApp Web
// (WAWebMexFetchAllSubgroupsJob). O grupo de avisos vem primeiro, com IsDefaultSubGroup.
// A lista inclui os grupos de que a conta não participa.
//
// Se o MEX falhar sem uma resposta definitiva sobre o grupo (401, 403, 404 ou JID que não é de
// comunidade), a consulta é refeita pelo IQ <sub_groups/> antigo. Nesse caso só JID, nome e
// IsDefaultSubGroup vêm preenchidos.
func (cli *Client) GetCommunitySubGroups(ctx context.Context, community types.JID) ([]*types.CommunitySubGroup, error) {
	groups, err := cli.fetchSubGroupsMex(ctx, community)
	if err == nil {
		return groups, nil
	}
	if errors.Is(err, errMexGroupNotCommunity) {
		return nil, err
	}
	mapped, definitive := mapMexGroupError(err, nil)
	if definitive || ctx.Err() != nil {
		return nil, mapped
	}
	cli.Log.Warnf("Failed to get subgroups of %s via MEX, falling back to IQ: %v", community, err)
	targets, iqErr := cli.getSubGroupsIQ(ctx, community)
	if iqErr != nil {
		return nil, iqErr
	}
	groups = make([]*types.CommunitySubGroup, len(targets))
	for i, target := range targets {
		groups[i] = &types.CommunitySubGroup{GroupLinkTarget: *target}
	}
	return groups, nil
}

func (cli *Client) fetchSubGroupsMex(ctx context.Context, community types.JID) ([]*types.CommunitySubGroup, error) {
	data, err := cli.sendMexIQ(ctx, queryFetchAllSubgroups, map[string]any{
		"group_id":      community.String(),
		"query_context": groupQueryContextInteractive,
	})
	if err != nil {
		return nil, err
	}
	return parseMexSubGroups(data)
}

func parseMexSubGroups(data json.RawMessage) ([]*types.CommunitySubGroup, error) {
	var resp respFetchAllSubgroups
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse subgroups response: %w", err)
	}
	group := resp.Group
	if group == nil {
		return nil, fmt.Errorf("missing xwa2_group_query_by_id in subgroups response")
	}
	if group.TypeName != "" && group.TypeName != mexTypeCommunityGroup {
		return nil, fmt.Errorf("%w (%s)", errMexGroupNotCommunity, group.TypeName)
	}
	if group.DefaultSubGroup == nil {
		return nil, fmt.Errorf("missing announcement group in subgroups response")
	}
	if group.SubGroups == nil {
		return nil, fmt.Errorf("missing edges in subgroups response")
	}
	defaultSub, err := group.DefaultSubGroup.toCommunitySubGroup(true)
	if err != nil {
		return nil, err
	}
	result := make([]*types.CommunitySubGroup, 0, len(group.SubGroups.Edges)+1)
	result = append(result, defaultSub)
	for _, edge := range group.SubGroups.Edges {
		if edge == nil || edge.Node == nil {
			return nil, fmt.Errorf("null node in subgroups response")
		}
		sub, err := edge.Node.toCommunitySubGroup(false)
		if err != nil {
			return nil, err
		}
		result = append(result, sub)
	}
	return result, nil
}

func (sub *mexCommunitySubGroup) toCommunitySubGroup(isDefault bool) (*types.CommunitySubGroup, error) {
	jid, err := parseMexGroupID(sub.ID)
	if err != nil {
		return nil, err
	}
	parsed := &types.CommunitySubGroup{
		GroupLinkTarget: types.GroupLinkTarget{
			JID:               jid,
			GroupIsDefaultSub: types.GroupIsDefaultSub{IsDefaultSubGroup: isDefault},
		},
	}
	if sub.Subject != nil {
		parsed.Name = sub.Subject.Value
		parsed.NameSetAt = parseMexUnixTime(sub.Subject.CreationTime)
	}
	if sub.Properties != nil {
		parsed.IsGeneralChat = sub.Properties.GeneralChat
		parsed.IsHidden = sub.Properties.HiddenGroup
		parsed.MembershipApprovalMode = sub.Properties.MembershipApprovalModeEnabled
	}
	if sub.MembershipApprovalRequests != nil {
		parsed.HasMembershipRequest = sub.MembershipApprovalRequests.TotalCount > 0
	}
	return parsed, nil
}

// parseMexGroupID aceita o JID completo ou só o usuário do grupo.
func parseMexGroupID(id string) (types.JID, error) {
	if id == "" {
		return types.EmptyJID, fmt.Errorf("missing group id in subgroups response")
	}
	if !strings.ContainsRune(id, '@') {
		return types.NewJID(id, types.GroupServer), nil
	}
	jid, err := types.ParseJID(id)
	if err != nil {
		return types.EmptyJID, fmt.Errorf("invalid group id %q in subgroups response: %w", id, err)
	}
	return jid, nil
}

// parseMexUnixTime lê um horário em segundos que pode vir como número ou como string.
func parseMexUnixTime(raw json.RawMessage) time.Time {
	value := strings.Trim(string(raw), `"`)
	if value == "" || value == "null" {
		return time.Time{}
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}
