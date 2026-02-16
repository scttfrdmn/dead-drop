document.getElementById('uploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const fileInput = document.getElementById('fileInput');
    const spinner = document.getElementById('uploadSpinner');
    const receipt = document.getElementById('receipt');
    const error = document.getElementById('uploadError');

    if (!fileInput.files[0]) {
        error.textContent = 'Please select a file';
        error.style.display = 'block';
        return;
    }

    receipt.style.display = 'none';
    error.style.display = 'none';
    spinner.style.display = 'block';

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        const response = await fetch('/submit', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Dead-Drop-Upload': 'true'
            }
        });

        spinner.style.display = 'none';

        if (!response.ok) {
            throw new Error('Upload failed');
        }

        const data = await response.json();

        document.getElementById('dropIdCode').textContent = data.drop_id;
        document.getElementById('receiptCode').textContent = data.receipt;
        document.getElementById('fileHashCode').textContent = data.file_hash;
        receipt.style.display = 'block';

        fileInput.value = '';

    } catch (err) {
        spinner.style.display = 'none';
        error.textContent = 'Upload failed: ' + err.message;
        error.style.display = 'block';
    }
});

document.getElementById('retrieveForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const dropId = document.getElementById('retrieveId').value.trim();
    const receiptCode = document.getElementById('retrieveReceipt').value.trim();
    const error = document.getElementById('retrieveError');
    error.style.display = 'none';

    if (!dropId || !receiptCode) {
        error.textContent = 'Both drop ID and receipt are required';
        error.style.display = 'block';
        return;
    }

    try {
        const response = await fetch('/retrieve?id=' + encodeURIComponent(dropId) + '&receipt=' + encodeURIComponent(receiptCode));

        if (!response.ok) {
            throw new Error('Retrieval failed - check your drop ID and receipt');
        }

        const disposition = response.headers.get('Content-Disposition');
        let filename = 'download';
        if (disposition) {
            const match = disposition.match(/filename="?([^"]+)"?/);
            if (match) filename = match[1];
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

    } catch (err) {
        error.textContent = err.message;
        error.style.display = 'block';
    }
});
