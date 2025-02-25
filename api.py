from flask import Flask, Response
import matplotlib.pyplot as plt
import io

app = Flask(__name__)

@app.route('/graph')
def generate_graph():
    # Create a figure
    fig, ax = plt.subplots()
    ax.plot([1, 2, 3, 4, 5], [10, 20, 25, 30, 40])  # Example data

    # Save the plot to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)

    return Response(buf.getvalue(), mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True)
