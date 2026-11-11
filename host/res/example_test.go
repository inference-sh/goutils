package res_test

import (
	"context"
	"fmt"

	"github.com/inference-sh/goutils/host/res"
)

// A unit written, systemd reloaded and the service restarted when the
// unit changed, then the service enabled and running. Run twice, the
// second run changes nothing.
func Example() {
	x := res.OSExec{Path: res.RootPath}
	apt := &res.Apt{Exec: x}
	restart := &res.Handler{Name: "restart nginx", Resource: &res.Restart{Exec: x, Name: "nginx"}}
	play := res.Play{
		Tasks: []res.Task{
			{Name: "the package lists", Resource: apt.Update(0)},
			{Name: "nginx", Resource: apt.Install("nginx")},
			{Name: "the site", Notify: []*res.Handler{restart}, Resource: &res.File{
				Path: "/etc/nginx/conf.d/site.conf", Content: []byte("server { listen 8080; }\n"), Mode: 0o644}},
			{Name: "nginx runs", Resource: &res.Service{Exec: x, Name: "nginx", Enabled: true, Running: true}},
		},
		Handlers: []*res.Handler{restart},
	}
	r := &res.Runner{OnResult: func(r res.Result) { fmt.Printf("%s: %s %s\n", r.Status, r.Name, r.Msg) }}
	if err := r.Run(context.Background(), play); err != nil {
		fmt.Println(err)
	}
}
