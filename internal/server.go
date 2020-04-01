package internal

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	auth "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	response := auth.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: auth.SchemeGroupVersion.String(),
			Kind:       "TokenReview",
		},
	}

	if identity, err := fromRequest(r); err != nil {
		log.Info(err)
		response.Status = auth.TokenReviewStatus{
			Authenticated: false,
			Error:         fmt.Sprintf("%v", err),
		}
	} else {
		response.Status = auth.TokenReviewStatus{
			Authenticated: true,
			User: auth.UserInfo{
				UID:      identity.UID,
				Username: identity.Username,
				Groups:   identity.Groups,
			},
			Error: "",
		}
	}

	json.NewEncoder(w).Encode(response)
}

func fromRequest(r *http.Request) (Identity, error) {
	decoder := json.NewDecoder(r.Body)

	var tokenReview auth.TokenReview
	if err := decoder.Decode(&tokenReview); err != nil {
		return Identity{}, fmt.Errorf("decode request body: %v", err)
	}

	identity, err := validate(tokenReview.Spec.Token)
	if err != nil {
		return Identity{}, err
	}

	return identity, nil
}
