FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
ENV PORT 8080
EXPOSE 8080
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:$PORT", "app:app"]
