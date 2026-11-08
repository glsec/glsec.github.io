// Keeps this directory out of the site's Go module, so go test ./... and the
// linters don't walk node_modules. It holds the npm tooling of the site checks
// and no Go code.
module site-checks

go 1.26.0
