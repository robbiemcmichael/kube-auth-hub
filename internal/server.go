package internal

import (
	"encoding/json"
	"net/http"

        auth "k8s.io/api/authentication/v1"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Handler(w http.ResponseWriter, r *http.Request) {
        tokenReview := auth.TokenReview{
                TypeMeta: metav1.TypeMeta{
                        APIVersion: auth.SchemeGroupVersion.String(),
                        Kind:       "TokenReview",
                },
                Status: auth.TokenReviewStatus{
                        Authenticated: true,
                        User: auth.UserInfo{
                                UID:      "id",
                                Username: "username",
                                Groups:   []string{"group"},
                        },
                        Error: "",
                },
        }

        json.NewEncoder(w).Encode(tokenReview)
}
