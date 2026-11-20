package main

import (
	"os"
	"path/filepath"
)

// protectedCookieFiles lists the browser cookie / login store files under
// the protected roots. These are included in every scan: the owner requires
// browser cookies to always be covered, and scanning the handful of store
// files is cheap compared to whole profile folders.
func protectedCookieFiles(protected []string) []string {
	names := []string{"Cookies", "Login Data", "Web Data"}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if seen[p] {
			return
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, root := range protected {
		// Chromium: <root>\<Profile>\Network\Cookies, <root>\<Profile>\Cookies…
		profiles, _ := filepath.Glob(filepath.Join(root, "*"))
		profiles = append(profiles, root)
		for _, prof := range profiles {
			for _, n := range names {
				add(filepath.Join(prof, n))
				add(filepath.Join(prof, "Network", n))
			}
		}
		// Firefox: cookies.sqlite / logins.json directly in the profile dir.
		add(filepath.Join(root, "cookies.sqlite"))
		add(filepath.Join(root, "logins.json"))
	}
	return out
}
