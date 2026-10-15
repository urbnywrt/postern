// web/ is the React UI, not Go. This file makes it a module of its own, so
// that the module of the repository ends here: ./... of the repository leaves
// out the Go files that npm packages bring into web/node_modules.
module github.com/urbnywrt/postern/web

go 1.27
