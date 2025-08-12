const blacklist = [
    "DROP", "DELETE", "UPDATE", "INSERT", "--", ";", "xp_cmdshell",
    "EXEC", "UNION", "SELECT *", " OR ", "1=1", "/*", "*/"
];

exports.blacklistCheck = (input) => {
    const upperQuery = input.toUpperCase();
    for (const word of blacklist) {
        if (upperQuery.includes(word)) {
            return false;
        }
    }
    return true;
};