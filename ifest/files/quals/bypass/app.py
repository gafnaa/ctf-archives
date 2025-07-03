from flask import Flask, request, render_template, render_template_string
import re 

app = Flask(__name__)

# Filter returns True if there is some pesky intruder
def filter(data):
    blacklist_words = ['.', '[', ']', '{{', '}}', '"', 'os', 'modules', 'base', 'import', 'application', 'builtins', "*"]
    additional_check = ['_', '__']
    additional_check = re.compile('|'.join(map(re.escape, additional_check)))

    for word in blacklist_words:
        if word in data:
            return True 
    
    return additional_check.match(data)

@app.route("/")
def index():
    title = request.args.get('title', 'Your title', type=str)
    content = request.args.get('content', "Multiple lines of text that form the lede, informing new readers quickly and efficiently about what's interesting in the content", type=str)

    if filter(title) or filter(content):
        title = "Oops..."
        content = "Nice try, but you got blocked by our super secure filtering"

    try:
        title = render_template_string(title)
        content = render_template_string(content)
    except Exception:
        title = "Error"
        content = "Ouch! Some error has occured"

    return render_template("index.html", title=title, content=content)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8888, debug=False) 