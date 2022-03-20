'use strict';

const { Sequelize } = require('sequelize');
const { sequelize, User } = require('../models');


module.exports = class UtilsServices {
    constructor() {}

    async getPagination(page, size) {
        const limit = parseInt(size) ? parseInt(size):3;
        const offset = page ? page * limit:0;
        return { limit, offset };
    };

    async getPagingData(data, page, limit) {
        const { count: totalItems, rows: items } = data;
        const currentPage = page ? +page : 0;
        const totalPages = Math.ceil(totalItems / limit);
        return { totalItems, items, totalPages, currentPage };
    };
}