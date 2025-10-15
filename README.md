# NThashgenerator

Small, dependency-free NT hash (MD4 over UTF-16-LE) generator.

## Usage

```bash
# single password
python3 nthashgenerator.py "purPLE9795!@"

# read password from stdin
echo -n "purPLE9795!@" | python3 nthashgenerator.py -