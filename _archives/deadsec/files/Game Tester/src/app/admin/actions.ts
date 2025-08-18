'use server';

export async function runOnServer(data: { codeArray: string }) {
  try {
    const { codeArray } = data;
    if (!codeArray || !codeArray.trim()) return 'Please enter a valid string.';
    const charCodes = JSON.parse(codeArray);
    if (charCodes.some((n: number) => n >= 65 && n <= 122)) {
      throw new Error('Invalid character detected.');
    }
    const verified_code = String.fromCharCode(...charCodes);
    const result = new Function(verified_code)();
    return result !== undefined ? String(result) : 'Code executed successfully.';
  } catch (e: any) {
    return e.message || 'Error occurred while executing code.';
  }
}
