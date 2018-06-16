# onchange

a daemon to trigger a command line when a resource changed.

# usage

```sh
onchange <resource> <command>

  -d duration
      pause between each test of the resource (default 1s)
  -fp string
      the prefered way to computethe finger print of a resource, one of etag|body|mod|re
  -q	stfu
  -re string
      the text that the resource should contain and the daemon should use to identify an update

onchange README.md echo changed
onchange -q README.md echo changed
onchange -q -d 5s README.md echo changed
onchange -q -d 5s -fp re -re "</html>" http://google.com echo changed


onchange -q test.file echo changed &
sleep 1;touch test.file
sleep 1;echo "some" > test.file
sleep 1;rm test.file
sleep 1;pkill onchange
```

# install

  go get github.com/mh-cbon/onchange
