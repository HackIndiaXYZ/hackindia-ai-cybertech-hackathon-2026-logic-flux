run:    ; python wsgi.py
test:   ; python -W ignore -m unittest discover -s tests -v
docker: ; docker build -t sentineltrace . && docker run --rm -p 8000:8000 -v st-data:/data sentineltrace
