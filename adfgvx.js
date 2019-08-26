var adfgvxCipher = function (selector, message, keyword1, keyword2) {
    var pA = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9"];
    var adfgvx = "ADFGVX";

    // clean keyword1, swap j for i, remove repeated letters
    var cleanKey1 = [];
    var char = "";
    for (var i = 0; i < keyword1.length; i ++) {
        char = keyword1[i].toLowerCase();
        if (((char >= "a") && (char <= "z")) || ((char >= "0") && (char <= "9"))) {
            if (cleanKey1.indexOf(char) === -1) {
                cleanKey1.push(char);
            }
        }
    }
    //console.log("Fractionation key: " + cleanKey1);

    // clean keyword2, remove repeated letters
    var cleanKey2 = [];
    var char = "";
    for (var i = 0; i < keyword2.length; i ++) {
        char = keyword2[i].toLowerCase();
        if ((char >= "a") && (char <= "z")) {
            if (cleanKey2.indexOf(char) === -1) {
                cleanKey2.push(char);
            }
        }
    }
    //console.log("Transposition key: " + cleanKey2);
    
    // construct ciphertext alphabet
    var cA = [];
    for (var i = 0; i < cleanKey1.length; i ++) {
        cA[i] = cleanKey1[i].toUpperCase();
    }
    for (var i = 0; i < pA.length; i ++) {
        char = pA[i];
        if ((char >= "a") && (char <= "z")) {
            char = char.toUpperCase();
        }
        if (cA.indexOf(char) === -1) {
            cA.push(char);
        }
    }
    //console.log("Ciphertext Alphabet: " + cA);

    // construct square for display
    var psq = "";
    for (var c = 0; c < 6; c ++) {
        for (var r = 0; r < 6; r ++) {
            psq += cA[(c * 6) + r] + " ";
        }
        psq += "\n";
    }
    //console.log("Square for Ciphertext Alphabet:\n" + psq);    

    // get column order from cleanKey2
    var order = [];
    for (var i = 0; i < cleanKey2.length; i ++) {
        order.push(pA.indexOf(cleanKey2[i]));
    }
    //console.log("Char order from transposition key: " + order);

    var columnOrder = [];
    for (var currentNum = 0; currentNum < order.length; currentNum ++) {
        var position = 0;
        for (var list = 0; list < order.length; list ++) {
            if (order[currentNum] > order[list]) {
                position += 1;
            }
        }
        columnOrder.push(position);
    }
    //console.log("Column order from transposition key: " + columnOrder);
    
    // encryption process
    if (selector === "encrypt") {
        // clean up message
        var cleanMessage = [];
        var char = "";
        for (var i = 0; i < message.length; i ++) {
            char = message[i].toLowerCase();
            if (((char >= "a") && (char <= "z")) || ((char >= "0") && (char <= "9"))) {
                cleanMessage.push(char);
            }
        }
        //console.log("Cleartext: " + cleanMessage);
        //console.log("Cleartext Length: " + cleanMessage.length);
        
        // get ADFGVX codes for message characters
        var fractionated = [];
        for (var i = 0; i < cleanMessage.length; i ++) {
            var p = cA.indexOf(cleanMessage[i].toUpperCase());
            var pD = Math.floor(p / 6);
            var pM = (p % 6);
            fractionated.push(adfgvx[pM]);
            fractionated.push(adfgvx[pD]);
        }
        //console.log("Fractionated: " + fractionated);

        // lay codes on grid
        var columns = cleanKey2.length;
        var rows = Math.floor(fractionated.length / cleanKey2.length) + 1;
        //console.log("c/r " + columns + " " + rows);

        // read off half codes by column
        var colForm = [];
        for (var co = 0; co < columns; co ++) {
            var tmpCol = "";
            for (var ro =0; ro < rows; ro ++) {
                if (((ro * columns) + co) < fractionated.length) {
                    tmpCol += fractionated[(ro * columns) + co];
                }
            }
            colForm.push(tmpCol);
        }
        //console.log("Read by Column: " + colForm);

        // shuffle columns by transposition keyword
        var output = "";
        for (var co = 0; co < columns; co ++) {
            output += colForm[columnOrder[co]];
            output += " ";
        }
        //console.log("Ciphertext: " + output);
    }

    
    // decryption process
    if (selector === "decrypt") {

        // clean up message and chunk it by spaces
        var messageChunks = [];
        var currentChunk = [];
        for (var i = 0; i < message.length; i ++) {
            char = message[i];
            char = char.toUpperCase();
            if (adfgvx.indexOf(char) != -1) {
                currentChunk.push(char);
            }
            else {
                messageChunks.push(currentChunk);
                currentChunk = [];
            }
        }
        if (currentChunk.length > 0) {
            messageChunks.push(currentChunk);
        }

        // display chunks and find longest one
        var longChunkLen = 0;
        for (var disp = 0; disp < cleanKey2.length; disp ++) {
            //console.log(messageChunks[disp]);
            var currChunkLen = messageChunks[disp].length;
            if (currChunkLen > longChunkLen) {
                longChunkLen = currChunkLen;
            }
        }
        //console.log("Longest chunk = " + longChunkLen);

        // swap chunks around by colOrder
        var orderedChunks = [];
        var emptyChunk = [];
        for (var k2 = 0; k2 < cleanKey2.length; k2 ++) {
            orderedChunks.push(emptyChunk);
        }

        for (var col = 0; col < columnOrder.length; col ++) {
            orderedChunks[columnOrder[col]] = messageChunks[col];
        }
        //console.log("Chunks after transposition by key 2: " + orderedChunks);

        // read off columns
        var gridOrder = [];
        for (var l = 0; l < longChunkLen; l ++) {
            for (var c = 0; c < cleanKey2.length; c ++) {
                if (l < orderedChunks[c].length) {
                    gridOrder.push(orderedChunks[c][l]);
                }
            }
        }
        //console.log("Original grid order: " + gridOrder + " length " + gridOrder.length);
        if ((gridOrder.length % 2) == 0) {

            // get plaintext characters from grid
            var output = "";
            for (var pair = 0; pair < gridOrder.length; pair += 2 ) {
                var top = adfgvx.indexOf(gridOrder[pair]);
                var side = adfgvx.indexOf(gridOrder[pair + 1]);
                var ptPos = top + (side * 6);
                output += cA[ptPos].toLowerCase();
            }
        }
        else {
            output = "It's not possible to generate plaintext from the combination of supplied ciphertext and transposition key.";
        }
    }

    return output;
};
