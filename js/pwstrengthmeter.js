/*
 * @param fieldEl {HTMLInput} The password field whose "onkeyup" event will be monitored.
 *
 * @param meterEl {HTMLElement} The password strength meter element whose className attribute will be updated
 *      based on the status (valid or invalid) and range (weak, good, or strong) of the password.
 *
 * @param opts {Object} Optional configuration arguments that can be passed in to tailor the functionality of
 *      the class.
 *
 *      @config onChange {function} Listener to call whenever the password is changed. Returning false will
 *          cancel the setting of classNames on the meterEl. The function will be passed an object with the
 *          following attributes:
 *          {
 *              password: < The user's password >,
 *              inDict: < Boolean indicating whether the password matches a dictionary entry >,
 *              entropy: < The entropy value of the password >,
 *              valid: < Boolean indicating whether the password passed all of the rules >,
 *              range:  < Object of range that the password matched >,
 *              invalidRules: < Array of the rules that failed to validate. Empty if valid is true >
 *          }
 *
 *      @config ranges {Object[]} An array of range objects that define a minimum and maximum number for a range that
 *          the password's calculated bits that will be compared against to determine if they fit in the given range.
 *          The cls attribute will be applied to the meterEl whenever the rule matches the calculated bitRange.
 *          The default ranges are:
 *          [
 *              { min: Number.NEGATIVE_INFINITY, max: 0, cls: "empty"},
 *              { min: 0, max: 56, cls: "weak"},
 *              { min: 56, max: 80, cls: "good" },
 *              { min: 80, max: Number.POSITIVE_INFINITY, cls: "strong" }
 *          ]
 *
 *      @config rules {Object[]} An array of rule objects that will be tested agains the password.  Each rule object must
 *          have a "regex" attribute that will be tested via "regex.test(password)" and compared to the "result"
 *          boolean attribute to determine whether the rule has been successfully fulfilled. Default is no rules (ie []).
 *          Example of an array of rules:
 *          [
 *              {regex: /.{8,}/, result: true },   // length >= 8
 *              {regex: /[a-z]/i, result: true },  // Must contain at least one alpha character
 *              {regex: /[\W_]/, result: true },   // Must contain one symbol
 *              {regex: /^\d/, result: false }     // Cannot start with a number
 *          ]
 *
 *      @config clsValid {String} Optional class added to meterEl when the password is valid. Default is "valid".
 *
 *      @config clsInvalid {String} Optional class added to meterEl when the password is invalid. Default is "invalid".
 *
 * }
 *
 */
var PWStrengthMeter = function (fieldEl, meterEl, opts) {
    var o;

    this.fieldEl = fieldEl;
    this.meterEl = meterEl;

    if (typeof opts == "object") {
        for (o in opts) {
            if (o in this) { this[o] = opts[o]; }
        }
    }

    // Add onkeyup listener to password field
    var fn = this.checkField.curry(this);
    if (fieldEl.addEventListener) {
        fieldEl.addEventListener('keyup', fn, false);
    } else if (fieldEl.attachEvent) {
        fieldEl.attachEvent('onkeyup', fn);
    }

    // Initialize the password strength meter
    this.checkField();
};


PWStrengthMeter.prototype = {

    fieldEl: null,
    meterEl: null,
    password: null,

    // opts
    ranges: [
        { min: Number.NEGATIVE_INFINITY, max: 0, cls: "empty"},
        { min: 0, max: 56, cls: "weak"},
        { min: 56, max: 80, cls: "good" },
        { min: 80, max: Number.POSITIVE_INFINITY, cls: "strong" }
    ],

    onChange: null,
    rules: [],
    clsValid: "valid",
    clsInvalid: "invalid",
    // eo opts


    checkField: function () {
        var entropyObj;

        // check if the password changed before proceeding
        if (this.fieldEl.value !== this.password) {
            // password has changed
            this.password = this.fieldEl.value;
            entropyObj = new Entropy(this.password);
            this.notify(entropyObj);
        };
    },


    /*
     * Callback function for whatever method we called to calculate the strength
     * of the password. Currently, we are using the Entropy Class to calculate
     * the bit strength of the given password.
     * @param info {Object} Data about the given password. Example Object would be:
     *          {
     *              password: "test",
     *              length: 4,
     *              bits: .224208765,
     *              entropy: 22.4,
     *              inDict: true,
     *              charset: { size: 128, count: 3 }
     *          }
     *
     * @return data {Object} Data associated with the password: entropy, inDict, validity, rules broken, ranges.
     */
    notify: function (info) {
        var pw = info.password,
            entropy = info.entropy,
            data = {
                password: pw,
                entropy: entropy,
                inDict: info.inDict,
                valid: true,
                invalidRules: [],
                range: null
            },
            i,
            rl,
            range,
            cancelCSS = false,
            mel = this.meterEl,
            cls;


        // Check the validity of the password by testing it against all of the rules
        for (i=0; i<this.rules.length; ++i) {
            rl = this.rules[i];
            if (rl.regex.test(pw) === !(rl.result === false)) {
                continue;  // nothing to do if valid
            } else {
                data.invalidRules[data.invalidRules.length] = this.clone(rl);
                data.valid = false;
            }
        }

        if (data.valid) {
            delete data.invalidRules
        }

        // Determine what "ranges" the password is based on it's bit value
        for (i=0; i<this.ranges.length; ++i) {
            range = this.ranges[i];
            if (entropy >= range.min && entropy <= range.max) {
                data.range = range;
                break;
            }
        }

        if (typeof this.onChange == "function") {
            cancelCSS = (this.onChange(data)===false);
        }

        if (!cancelCSS) {

            // Add the appropriate CSS classes to the meterEl based on the current
            // status of the password.
            this.removeClass( mel, (data.valid ? this.clsInvalid : this.clsValid));
            this.addClass( mel, (data.valid ? this.clsValid : this.clsInvalid));

            this.addClass(mel, range.cls||"");
            for (i=0; i<this.ranges.length; ++i) {
                cls = this.ranges[i].cls;
                if (cls != data.range.cls) {
                    this.removeClass(mel, cls)
                }
            }
        }

    },


    /**
     * Make a shallow copy of an object. The copy is NOT recursive (i.e. it is only one level deep).
     */
    clone: function (obj) {
        if (typeof obj != 'object'){
            return obj;
        }

        var newObj = {};
        for (var i in obj) {
            newObj[i] = obj[i];
        }
        return newObj;
    },

    addClass: function (el, cls) {
        var clsNms, ln, i;

        if ( el.nodeType === 1 && typeof cls === "string" ) {
            clsNms = (el.className || "").split( /\s+/ );
            ln=clsNms.length;
            for (i=0; i<ln; ++i) {
                if (clsNms[i] == cls) { return;  } // nothing to do if we find a matching classname
            }
            // Add the class
            clsNms[ln] = cls;
            el.className = clsNms.join(" ");
        }
    },

    removeClass: function (el, cls) {
        var clsNms, ln, i;

        if ( el.nodeType === 1 && typeof cls === "string" ) {
            clsNms = (el.className || "").split( /\s+/ );
            ln=clsNms.length;
            for (i=0; i<ln; ++i) {
                if (clsNms[i] == cls) {
                    clsNms.splice(i,1);
                    el.className = clsNms.join(" ");
                    return;
                }
            }
        }
    }

};


/**
 * Augment Function.prototype to give functions the ability to generate
 * closures with pre-defined scope and arguments. curry() MUST be called
 * as a method, ex.
 *      myFunction.curry();
 * NOT as a regular function, ex.
 *      var a = myFunction.curry; a();
 *
 * @param scope {Object} What the value of "this" will be when the function is called.
 *          Default is the Window object.
 * @param arguments {Any} Any arguments, after the scope, will be appended, as arguments,
 *          when the function is called.
 * @return {Function} A function that, when called, will have the pre-defined scope and
 *          arguments.
 */
if(!Function.prototype.curry) {
    (function () {
        var slice = Array.prototype.slice;

        Function.prototype.curry = function (scope /* arg_1, arg_2, ... arg_N */) {

            if (typeof this != "function") {
                throw {name: "TypeError", message: "curry must be called as a method"}
            }

            var args = slice.call(arguments, 1),
                fn = this;

            return function ( ) {
                // pre-pend any arguments that have been passed in before executing the function
                fn.apply(scope||this, slice.call(arguments).concat(args));
            };
        } // -- eo curry method

    })();
}

