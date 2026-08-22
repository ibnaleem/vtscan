package types

import "encoding/json"

func DecodeRelationshipsResponse(body []byte) ([]IPRelatedObject, IPRelationshipsMeta, error) {
	var resp IPRelationshipsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, IPRelationshipsMeta{}, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, resp.Meta, nil
	}

	var objects []IPRelatedObject
	if err := json.Unmarshal(resp.Data, &objects); err == nil {
		return objects, resp.Meta, nil
	}

	var single IPRelatedObject
	if err := json.Unmarshal(resp.Data, &single); err != nil {
		return nil, resp.Meta, err
	}
	if single.ID == "" {
		return nil, resp.Meta, nil
	}
	return []IPRelatedObject{single}, resp.Meta, nil
}
